package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"filippo.io/sunlight"
	"filippo.io/torchwood"

	"github.com/golang/glog"
	"github.com/hashicorp/go-metrics"

	"github.com/google/certificate-transparency-go/x509"

	"github.com/mozilla/crlite/go"
	"github.com/mozilla/crlite/go/storage"
)

type TiledLogWorker struct {
	Database   storage.CertDatabase
	Client     *sunlight.Client
	LogMeta    *types.CTLogMetadata
	Checkpoint torchwood.Checkpoint
	LogState   *types.CTLogState
	IssuerMap  *map[string]*x509.Certificate
	WorkOrder  LogWorkerTask
	BatchSize  uint64
	MetricKey  string
}

func NewTiledLogWorker(ctx context.Context, db storage.CertDatabase, ctLogMeta *types.CTLogMetadata, issuerMap *map[string]*x509.Certificate) (*TiledLogWorker, error) {
	batchSize := *ctconfig.BatchSize

	logUrlObj, err := url.Parse(ctLogMeta.URL)
	if err != nil {
		glog.Errorf("[%s] Unable to parse CT Log URL: %s", ctLogMeta.URL, err)
		return nil, err
	}

	logObj, err := db.GetLogState(logUrlObj)
	if err != nil {
		glog.Errorf("[%s] Unable to get cached CT Log state: %s", ctLogMeta.URL, err)
		return nil, err
	}

	if logObj.LogID != ctLogMeta.LogID {
		// The LogID shouldn't change, but we'll treat the input as
		// authoritative. Old versions of ct-fetch didn't store the
		// LogID in redis, so we will hit this on upgrade.
		logObj.LogID = ctLogMeta.LogID
	}

	if logObj.MMD != uint64(ctLogMeta.MMD) {
		// Likewise storing MMD is new.
		logObj.MMD = uint64(ctLogMeta.MMD)
	}

	publicKey, err := ctLogMeta.PublicKey()

	client, err := sunlight.NewClient(&sunlight.ClientConfig{
		MonitoringPrefix: ctLogMeta.URL,
		PublicKey:        publicKey,
		UserAgent:        userAgent,
	})
	if err != nil {
		glog.Errorf("[%s] Unable to construct CT log client: %s", ctLogMeta.URL, err)
		return nil, err
	}

	metricKey := ctLogMeta.MetricKey()

	checkpoint, _, fetchErr := client.Checkpoint(ctx)

	// Determine what the worker should do.
	var task LogWorkerTask
	if fetchErr != nil {
		// Temporary network failure?
		glog.Warningf("[%s] Unable to fetch signed tree head: %s", ctLogMeta.URL, fetchErr)
		task = Sleep
	} else {
		metrics.SetGauge([]string{metricKey, "coverage"}, float32(logObj.MaxEntry-logObj.MinEntry+1)/float32(checkpoint.Tree.N))

		if logObj.MaxEntry+batchSize < uint64(checkpoint.Tree.N) {
			// There are many new entries to download.
			task = Update
		} else if time.Since(logObj.LastUpdateTime) < 10*time.Minute {
			// There are few new entries, and we updated recently.
			task = Sleep
		} else if logObj.MaxEntry+1 < uint64(checkpoint.Tree.N) {
			// There is at least one new entry and we haven't
			// downloaded anything recently.
			task = ForceUpdate
		} else {
			// There are no new entries.
			task = Sleep
		}
	}

	return &TiledLogWorker{
		Database:   db,
		Client:     client,
		LogState:   logObj,
		LogMeta:    ctLogMeta,
		Checkpoint: checkpoint,
		IssuerMap:  issuerMap,
		WorkOrder:  task,
		BatchSize:  batchSize,
		MetricKey:  metricKey,
	}, nil
}

// Helper function borrowed from
// https://github.com/FiloSottile/torchwood/blob/b067ac9d4cf6836cb59633e380453d60a5bee16c/tlogclient.go#L512
func parseRetryAfter(header string) time.Time {
	if header == "" {
		return time.Time{}
	}
	n, err := strconv.Atoi(header)
	if err == nil {
		return time.Now().Add(time.Duration(n) * time.Second)
	}
	t, err := http.ParseTime(header)
	if err == nil {
		return t
	}
	return time.Time{}
}

// GetCertificate retrieves a certificate from cache or fetches it over the network.
//
// Error returns:
//
//	(nil, nil) indicates an intermittent network error,
//	(nil, err) indicates a fatal error that should halt log ingestion.
func (lw TiledLogWorker) GetCertificate(ctx context.Context, fingerprint string) (*x509.Certificate, error) {
	cert, prs := (*lw.IssuerMap)[fingerprint]
	if prs {
		return cert, nil
	}

	uri, err := url.JoinPath(lw.LogMeta.URL, "issuer", fingerprint)
	if err != nil {
		return nil, err
	}
	glog.Infof("[%s] Fetching %s", lw.Name(), uri)

	/* For consistency with the tile fetcher, this HTTP request / retry
	 * loop is borrowed from
	 * https://github.com/FiloSottile/torchwood/blob/b067ac9d4cf6836cb59633e380453d60a5bee16c/tlogclient.go#L460
	 */
	req, err := http.NewRequestWithContext(ctx, "GET", uri, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create request: %w", uri, err)
	}
	var errs error
	var retryAfter time.Time
	for j := range 5 {
		if j > 0 {
			// Wait 1s, 5s, 25s, or 125s before retrying.
			pause := time.Duration(math.Pow(5, float64(j-1))) * time.Second
			if !retryAfter.IsZero() {
				pause = time.Until(retryAfter)
				retryAfter = time.Time{}
			}
			glog.Infof("[%s] waiting %s to retry GET request %s (%w)", lw.Name(), pause, uri, errs)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(pause):
			}
		}
		req.Header.Set("User-Agent", userAgent)
		resp, err := httpClient.Do(req)
		if err != nil {
			errs = errors.Join(errs, err)
			continue
		}
		defer resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
			retryAfter = parseRetryAfter(resp.Header.Get("Retry-After"))
			errs = errors.Join(errs, fmt.Errorf("unexpected status code %d", resp.StatusCode))
			continue
		case resp.StatusCode != http.StatusOK:
			// We'll try again later
			return nil, nil
		}
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			errs = errors.Join(errs, err)
			continue
		}

		cert, err := x509.ParseCertificate(data)
		if cert == nil {
			return nil, fmt.Errorf("[%s] Fatal parsing error: fingerprint: %s error: %s", lw.Name(), fingerprint, err)
		}
		if err != nil {
			glog.Warningf("[%s] Nonfatal parsing error: fingerprint: %s error: %s", lw.Name(), fingerprint, err)
		}

		(*lw.IssuerMap)[fingerprint] = cert
		return cert, nil
	}
	glog.Warningf("[%s] Errors retrieving issuer cert %s: %w", lw.Name(), fingerprint, errs)
	return nil, nil
}

func (lw TiledLogWorker) Name() string {
	return lw.LogMeta.URL
}

func (lw *TiledLogWorker) sleep(ctx context.Context) {
	// Sleep for ctconfig.PollingDelay seconds (+/- 10%).
	jitteredPollingDelay := (1 + 0.1*rand.NormFloat64()) * float64(*ctconfig.PollingDelay)
	duration := time.Duration(jitteredPollingDelay) * time.Second
	glog.Infof("[%s] Stopped. Sleeping for %d seconds", lw.Name(), int(jitteredPollingDelay))
	select {
	case <-ctx.Done():
		glog.Infof("[%s] Signal caught. Exiting.", lw.Name())
	case <-time.After(duration):
	}
}

// storeLogEntry attempts to submit a certificate to entryChan. It may block to
// request an issuer's certificate over the network.
//
// Return codes:
//   - (true, nil) indicates that logEntry was processed successfully,
//   - (false, nil) indicates that there was a network error and that the TiledLogWorker should go to sleep,
//   - (false, err) indicates a fatal error that should halt log ingestion.
func (lw *TiledLogWorker) storeLogEntry(ctx context.Context, logEntry *sunlight.LogEntry, entryChan chan<- CtLogEntry) (bool, error) {
	var cert *x509.Certificate
	var err error
	if logEntry.IsPrecert {
		cert, err = x509.ParseCertificate(logEntry.PreCertificate)
	} else {
		cert, err = x509.ParseCertificate(logEntry.Certificate)
	}
	if cert == nil {
		return false, fmt.Errorf("[%s] Fatal parsing error: index: %d error: %s", lw.Name(), logEntry.LeafIndex, err)
	}
	if err != nil {
		glog.Warningf("[%s] Nonfatal parsing error: index: %d error: %s", lw.Name(), logEntry.LeafIndex, err)
	}

	if cert.NotAfter.Before(time.Now()) && !*ctconfig.LogExpiredEntries {
		// Skip expired certificate
		return true, nil
	}

	if len(logEntry.ChainFingerprints) < 1 {
		// Hard to imagine how this would happen, as even a self-signed
		// cert has a non-empty chain. But if it does happen we shouldn't
		// be relying on this CT log.
		return false, fmt.Errorf("[%s] No chain for certificate index=%d serial=%s subject=%+v issuer=%+v",
			lw.Name(), logEntry.LeafIndex, types.NewSerial(cert).String(), cert.Subject, cert.Issuer)
	}

	preIssuerOrIssuingCert, err := lw.GetCertificate(ctx, hex.EncodeToString(logEntry.ChainFingerprints[0][:]))
	if err != nil {
		return false, err
	}
	if preIssuerOrIssuingCert == nil {
		return false, nil
	}

	var issuingCert *x509.Certificate
	if types.IsPreIssuer(preIssuerOrIssuingCert) {
		if !logEntry.IsPrecert {
			glog.Warningf("[%s] X509LogEntry issuer has precertificate signing EKU: index: %d", lw.Name(), logEntry.LeafIndex)
		}

		if len(logEntry.ChainFingerprints) < 2 {
			// As above, this shouldn't happen.
			return false, fmt.Errorf("[%s] No issuer known for certificate index=%d serial=%s subject=%+v issuer=%+v",
				lw.Name(), logEntry.LeafIndex, types.NewSerial(cert).String(), cert.Subject, cert.Issuer)
		}

		issuingCert, err = lw.GetCertificate(ctx, hex.EncodeToString(logEntry.ChainFingerprints[1][:]))
		if err != nil {
			return false, err
		}
		if issuingCert == nil {
			return false, nil
		}
	} else {
		issuingCert = preIssuerOrIssuingCert
	}

	select {
	case <-ctx.Done():
		// The LogSyncEngine is shutting down, so it's OK to return an error here.
		return false, fmt.Errorf("[%s] Cancelled", lw.Name())
	case entryChan <- CtLogEntry{cert, issuingCert, logEntry.LeafIndex, lw.LogMeta}:
	}

	return true, nil
}

func (lw *TiledLogWorker) Run(ctx context.Context, entryChan chan<- CtLogEntry) error {
	// NOTE: If we return a non-nil error from this function we will stop
	// ingesting the log.

	if lw.WorkOrder == Sleep {
		lw.sleep(ctx)
		return nil
	}

	if !(lw.WorkOrder == Update || lw.WorkOrder == ForceUpdate) {
		return fmt.Errorf("Unexpected work order: %d", lw.WorkOrder)
	}

	minTimestamp := lw.LogState.MinTimestamp
	maxTimestamp := lw.LogState.MaxTimestamp
	maxEntry := lw.LogState.MaxEntry

	// readLogEntries mutably captures lw, ctx, maxEntry, minTimestamp,
	// and maxTimestamp.
	//
	// Return codes:
	//   - (true, nil): success
	//   - (false, nil): intermittent error, the TileLogWorker should sleep.
	//   - (false, err): fatal error, log ingestion should halt.
	readLogEntries := func() (bool, error) {
		for i, entry := range lw.Client.Entries(ctx, lw.Checkpoint.Tree, int64(maxEntry+1)) {
			keepGoing, err := lw.storeLogEntry(ctx, entry, entryChan)
			if !(keepGoing && err == nil) {
				return keepGoing, err
			}

			maxEntry = uint64(i)
			minTimestamp = uint64Min(minTimestamp, uint64(entry.Timestamp))
			maxTimestamp = uint64Max(maxTimestamp, uint64(entry.Timestamp))

			if maxEntry%lw.BatchSize == 0 {
				err := lw.saveState(maxEntry, minTimestamp, maxTimestamp)
				if err != nil {
					glog.Errorf("[%s] : Error saving log state %s", err)
					return false, err
				}
			}
		}

		err := lw.saveState(maxEntry, minTimestamp, maxTimestamp)
		if err != nil {
			glog.Errorf("[%s] : Error saving log state %s", lw.Name(), err)
			return false, err
		}

		err = lw.Client.Err()
		if err != nil {
			glog.Errorf("[%s] : Sunlight client error %s", lw.Name(), err)
			return false, nil
		}

		return true, nil
	}

	keepGoing, err := readLogEntries()
	if err != nil {
		return err
	}
	if !keepGoing {
		lw.sleep(ctx)
		return nil
	}
	if lw.WorkOrder == ForceUpdate {
		// The first readLogEntries() call may have stopped early to avoid
		// fetching a partial tile. Calling it again will fetch the partial
		// tile.
		keepGoing, err = readLogEntries()
		if err != nil {
			return err
		}
		if !keepGoing {
			lw.sleep(ctx)
			return nil
		}
	}

	return nil
}

func (lw *TiledLogWorker) saveState(maxEntry, minTimestamp, maxTimestamp uint64) error {
	lw.LogState.MinEntry = 0
	lw.LogState.MaxEntry = uint64Max(lw.LogState.MaxEntry, maxEntry)
	lw.LogState.MinTimestamp = uint64Min(lw.LogState.MinTimestamp, minTimestamp)
	lw.LogState.MaxTimestamp = uint64Max(lw.LogState.MaxTimestamp, maxTimestamp)
	lw.LogState.LastUpdateTime = time.Now()

	saveErr := lw.Database.SaveLogState(lw.LogState)
	if saveErr != nil {
		return fmt.Errorf("Database error: %s", saveErr)
	}

	glog.Infof("[%s] Saved log state: %s", lw.Name(), lw.LogState)
	return nil
}
