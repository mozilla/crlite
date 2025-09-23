package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/rand"
	"time"

	"filippo.io/sunlight"
	"filippo.io/torchwood"

	"github.com/golang/glog"
	"github.com/hashicorp/go-metrics"

	"github.com/google/certificate-transparency-go/x509"

	types "github.com/mozilla/crlite/go"
)

type TiledLogWorker struct {
	Client       *sunlight.Client
	LogMeta      *types.CTLogMetadata
	Checkpoint   torchwood.Checkpoint
	SthTimestamp uint64
	LogState     *types.CTLogState
	IssuerMap    *map[string]*x509.Certificate
	WorkOrder    LogWorkerTask
	BatchSize    uint64
	MetricKey    string
}

func NewTiledLogWorker(ctx context.Context, logObj *types.CTLogState, ctLogMeta *types.CTLogMetadata, issuerMap *map[string]*x509.Certificate) (*TiledLogWorker, error) {
	batchSize := *ctconfig.BatchSize

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
	if err != nil {
		glog.Errorf("[%s] Unable to get public key: %s", ctLogMeta.URL, err)
		return nil, err
	}

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

	checkpoint, n, fetchErr := client.Checkpoint(ctx)

	sthTimestamp := uint64(0)
	if n != nil && len(n.Sigs) > 0 {
		noteTimestamp, err := sunlight.RFC6962SignatureTimestamp(n.Sigs[0])
		if err != nil {
			glog.Errorf("[%s] Unable to parse note: %s", ctLogMeta.URL, err)
			return nil, err
		}
		sthTimestamp = uint64(noteTimestamp)
	}

	// Determine what the worker should do.
	var task LogWorkerTask
	if fetchErr != nil {
		// Temporary network failure?
		glog.Warningf("[%s] Unable to fetch signed tree head: %s", ctLogMeta.URL, fetchErr)
		task = RetryGetSTH
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
			task = Sleep
		}
	}

	return &TiledLogWorker{
		Client:       client,
		LogState:     logObj,
		LogMeta:      ctLogMeta,
		Checkpoint:   checkpoint,
		SthTimestamp: sthTimestamp,
		IssuerMap:    issuerMap,
		WorkOrder:    task,
		BatchSize:    batchSize,
		MetricKey:    metricKey,
	}, nil
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

	endpoint := "issuer/" + fingerprint
	glog.Infof("[%s] Fetching %s", lw.Name(), endpoint)

	data, err := lw.Client.Fetcher().ReadEndpoint(ctx, endpoint)
	if err != nil {
		glog.Warningf("[%s] Error retrieving issuer cert %s: %w", lw.Name(), fingerprint, err)
		return nil, nil
	}

	cert, err = x509.ParseCertificate(data)
	if cert == nil {
		return nil, fmt.Errorf("[%s] Fatal parsing error: fingerprint: %s error: %s", lw.Name(), fingerprint, err)
	}
	if err != nil {
		glog.Warningf("[%s] Nonfatal parsing error: fingerprint: %s error: %s", lw.Name(), fingerprint, err)
	}

	(*lw.IssuerMap)[fingerprint] = cert
	return cert, nil
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
func (lw *TiledLogWorker) storeLogEntry(ctx context.Context, logEntry *sunlight.LogEntry, entryChan chan<- LogSyncMessage) (bool, error) {
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
	case entryChan <- LogSyncMessage{cert, issuingCert, nil}:
	}

	return true, nil
}

func (lw *TiledLogWorker) Run(ctx context.Context, entryChan chan<- LogSyncMessage) error {
	// NOTE: If we return a non-nil error from this function we will stop
	// ingesting the log.

	minTimestamp := lw.LogState.MinTimestamp
	maxTimestamp := lw.LogState.MaxTimestamp
	maxEntry := lw.LogState.MaxEntry

	if lw.WorkOrder == RetryGetSTH {
		lw.sleep(ctx)
		return nil
	}

	if lw.WorkOrder == Sleep {
		// The coverage cutoff for CRLite filters is
		// `LogState.MaxTimestamp - LogState.MMD`. Normally
		// MaxTimestamp is the timestamp of an entry that we have seen
		// in the log. But if we are sleeping because there are no new
		// entries in the log, then we can set MaxTimestamp equal to
		// STH.Timestamp, because no new entries with a timestamp less
		// than `STH.Timestamp - LogState.MMD` will be added. This
		// ensures that we will eventually cover the tail of a log that
		// is no longer receiving new entries.
		if lw.LogState.MaxEntry+1 == uint64(lw.Checkpoint.Tree.N) {
			maxTimestamp = lw.SthTimestamp
			err := lw.updateState(ctx, maxEntry, minTimestamp, maxTimestamp, entryChan)
			if err != nil {
				glog.Errorf("[%s] : Error saving log state %s", lw.Name(), err)
				return err
			}
		}
		lw.sleep(ctx)
		return nil
	}

	if !(lw.WorkOrder == Update || lw.WorkOrder == ForceUpdate) {
		return fmt.Errorf("Unexpected work order: %d", lw.WorkOrder)
	}

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
				err := lw.updateState(ctx, maxEntry, minTimestamp, maxTimestamp, entryChan)
				if err != nil {
					glog.Errorf("[%s] : Error saving log state %s", err)
					return false, err
				}
			}
		}

		err := lw.updateState(ctx, maxEntry, minTimestamp, maxTimestamp, entryChan)
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

func (lw *TiledLogWorker) updateState(ctx context.Context, maxEntry uint64, minTimestamp uint64, maxTimestamp uint64, entryChan chan<- LogSyncMessage) error {
	lw.LogState.MinEntry = 0
	lw.LogState.MaxEntry = uint64Max(lw.LogState.MaxEntry, maxEntry)
	lw.LogState.MinTimestamp = uint64Min(lw.LogState.MinTimestamp, minTimestamp)
	lw.LogState.MaxTimestamp = uint64Max(lw.LogState.MaxTimestamp, maxTimestamp)
	lw.LogState.LastUpdateTime = time.Now()

	stateCopy := *lw.LogState
	select {
	case <-ctx.Done():
		return fmt.Errorf("[%s] Cancelled", lw.Name())
	case entryChan <- LogSyncMessage{nil, nil, &stateCopy}:
	}

	return nil
}
