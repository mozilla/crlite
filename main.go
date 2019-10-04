/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// Based on github.com/jcjones/ct-sql/

package main

import (
	"context"
	"math/rand"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/armon/go-metrics"
	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/jcjones/ct-mapreduce/config"
	"github.com/jcjones/ct-mapreduce/engine"
	"github.com/jcjones/ct-mapreduce/storage"
	"github.com/jcjones/ct-mapreduce/telemetry"
	"github.com/jpillora/backoff"
	"github.com/vbauerster/mpb"
	"github.com/vbauerster/mpb/decor"
)

var (
	ctconfig = config.NewCTConfig()
)

func certIsFilteredOut(aCert *x509.Certificate) bool {
	// Skip unimportant entries, if configured

	if aCert.NotAfter.Before(time.Now()) && !*ctconfig.LogExpiredEntries {
		return true
	}

	skip := (len(*ctconfig.IssuerCNFilter) != 0)
	for _, filter := range strings.Split(*ctconfig.IssuerCNFilter, ",") {
		if strings.HasPrefix(aCert.Issuer.CommonName, filter) {
			skip = false
			break
		}
	}

	glog.V(4).Infof("Skipping inserting cert issued by %s", aCert.Issuer.CommonName)
	return skip
}

func uint64ToTimestamp(timestamp uint64) *time.Time {
	t := time.Unix(int64(timestamp/1000), int64(timestamp%1000))
	return &t
}

type CtLogEntry struct {
	LogEntry *ct.LogEntry
	LogURL   string
}

// Coordinates all workers
type LogSyncEngine struct {
	ThreadWaitGroup     *sync.WaitGroup
	DownloaderWaitGroup *sync.WaitGroup
	database            storage.CertDatabase
	entryChan           chan CtLogEntry
	display             mpb.Progress
	cancelTrigger       context.CancelFunc
}

// Operates on a single log
type LogWorker struct {
	Bar        *mpb.Bar
	Database   storage.CertDatabase
	Client     *client.LogClient
	LogURL     string
	STH        *ct.SignedTreeHead
	LogState   *storage.CertificateLog
	StartPos   uint64
	EndPos     uint64
	SaveTicker *time.Ticker
	Backoff    *backoff.Backoff
}

func NewLogSyncEngine(db storage.CertDatabase) *LogSyncEngine {
	ctx, cancel := context.WithCancel(context.Background())
	twg := new(sync.WaitGroup)

	refreshDur, err := time.ParseDuration(*ctconfig.OutputRefreshPeriod)
	if err != nil {
		glog.Fatal(err)
	}
	glog.Infof("Progress bar refresh rate is every %s.\n", refreshDur.String())

	display := mpb.New(
		mpb.WithWaitGroup(twg),
		mpb.WithContext(ctx),
		mpb.WithRefreshRate(refreshDur),
	)

	return &LogSyncEngine{
		ThreadWaitGroup:     twg,
		DownloaderWaitGroup: new(sync.WaitGroup),
		database:            db,
		entryChan:           make(chan CtLogEntry, 16),
		display:             *display,
		cancelTrigger:       cancel,
	}
}

func (ld *LogSyncEngine) StartDatabaseThreads() {
	for t := 0; t < *ctconfig.NumThreads; t++ {
		go ld.insertCTWorker()
	}
}

// Blocking function, run from a thread
func (ld *LogSyncEngine) SyncLog(logURL string) error {
	worker, err := ld.NewLogWorker(logURL)
	if err != nil {
		return err
	}

	return worker.Run(ld.entryChan)
}

func (ld *LogSyncEngine) Stop() {
	close(ld.entryChan)
	ld.cancelTrigger()
	ld.display.Wait()
}

func (ld *LogSyncEngine) Cleanup() {
	err := ld.database.Cleanup()
	if err != nil {
		glog.Errorf("Cache cleanup error caught: %s", err)
	}
}

func (ld *LogSyncEngine) insertCTWorker() {
	ld.ThreadWaitGroup.Add(1)
	defer ld.ThreadWaitGroup.Done()
	for ep := range ld.entryChan {
		var cert *x509.Certificate
		var err error

		parseTime := time.Now()

		switch ep.LogEntry.Leaf.TimestampedEntry.EntryType {
		case ct.X509LogEntryType:
			cert = ep.LogEntry.X509Cert
		case ct.PrecertLogEntryType:
			cert, err = x509.ParseCertificate(ep.LogEntry.Precert.Submitted.Data)
		}

		if err != nil {
			glog.Errorf("Problem decoding certificate: index: %d error: %s", ep.LogEntry.Index, err)
			continue
		}

		if certIsFilteredOut(cert) {
			continue
		}

		if len(ep.LogEntry.Chain) < 1 {
			glog.Warningf("No issuer known for certificate log=%s index=%d serial=%+v issuer=%+v", ep.LogURL, ep.LogEntry.Index, *cert.SerialNumber, cert.Issuer)
			continue
		}

		issuingCert, err := x509.ParseCertificate(ep.LogEntry.Chain[0].Data)
		if err != nil {
			glog.Errorf("Problem decoding issuing certificate: index: %d error: %s", ep.LogEntry.Index, err)
			continue
		}
		metrics.MeasureSince([]string{"insertCTWorker-ParseCertificates"}, parseTime)

		storeTime := time.Now()
		err = ld.database.Store(cert, issuingCert, ep.LogURL, ep.LogEntry.Index)
		if err != nil {
			glog.Errorf("Problem inserting certificate: index: %d error: %s", ep.LogEntry.Index, err)
		}
		metrics.MeasureSince([]string{"insertCTWorker-Store"}, storeTime)
	}
}

func (ld *LogSyncEngine) NewLogWorker(ctLogUrl string) (*LogWorker, error) {
	ctLog, err := client.New(ctLogUrl, nil, jsonclient.Options{})
	if err != nil {
		glog.Errorf("[%s] Unable to construct CT log client: %s", ctLogUrl, err)
		return nil, err
	}

	glog.Infof("[%s] Fetching signed tree head... ", ctLogUrl)
	sth, err := ctLog.GetSTH(context.Background())
	if err != nil {
		glog.Errorf("[%s] Unable to fetch signed tree head: %s", ctLogUrl, err)
		return nil, err
	}

	// Set pointer in DB, now that we've verified the log works
	logUrlObj, err := url.Parse(ctLogUrl)
	if err != nil {
		glog.Errorf("[%s] Unable to parse Certificate Log: %s", ctLogUrl, err)
		return nil, err
	}
	logObj, err := ld.database.GetLogState(logUrlObj)
	if err != nil {
		glog.Errorf("[%s] Unable to set Certificate Log: %s", ctLogUrl, err)
		return nil, err
	}

	var startPos uint64
	// Now we're OK to use the DB
	if *ctconfig.Offset > 0 {
		glog.Infof("[%s] Starting from offset %d", ctLogUrl, *ctconfig.Offset)
		startPos = *ctconfig.Offset
	} else {
		glog.Infof("[%s] Counting existing entries... ", ctLogUrl)
		startPos = uint64(logObj.MaxEntry)
		if err != nil {
			glog.Errorf("[%s] Failed to read entries file: %s", ctLogUrl, err)
			return nil, err
		}
	}

	var endPos = sth.TreeSize
	if *ctconfig.Limit > 0 && (startPos+*ctconfig.Limit) < sth.TreeSize {
		endPos = startPos + *ctconfig.Limit
	}

	savePeriod, err := time.ParseDuration(*ctconfig.SavePeriod)
	if err != nil {
		glog.Errorf("Couldn't parse save period: %s err=%v", savePeriod, err)
		return nil, err
	}
	saveTicker := time.NewTicker(savePeriod)

	glog.Infof("[%s] %d total entries as of %s", ctLogUrl, sth.TreeSize, uint64ToTimestamp(sth.Timestamp).Format(time.ANSIC))

	progressBar := ld.display.AddBar((int64)(endPos-startPos),
		mpb.PrependDecorators(
			// display our name with one space on the right
			decor.Name(logObj.ShortURL, decor.WC{W: 30, C: decor.DidentRight}),
		),
		mpb.AppendDecorators(
			decor.Percentage(),
			decor.Name(""),
			decor.EwmaETA(decor.ET_STYLE_GO, 64, decor.WC{W: 14}),
			decor.CountersNoUnit("%d / %d", decor.WCSyncSpace),
		),
		mpb.BarRemoveOnComplete(),
	)

	return &LogWorker{
		Bar:        progressBar,
		Database:   ld.database,
		Client:     ctLog,
		LogState:   logObj,
		LogURL:     ctLogUrl,
		STH:        sth,
		StartPos:   startPos,
		EndPos:     endPos,
		SaveTicker: saveTicker,
		Backoff: &backoff.Backoff{
			Min:    10 * time.Millisecond,
			Max:    1 * time.Second,
			Jitter: true,
		},
	}, nil
}

func (lw *LogWorker) Run(entryChan chan<- CtLogEntry) error {
	defer lw.SaveTicker.Stop()

	glog.Infof("[%s] Going from %d to %d (%4.2f%% complete to head of log)", lw.LogURL, lw.StartPos, lw.EndPos, float64(lw.StartPos)/float64(lw.STH.TreeSize)*100)

	if lw.StartPos == lw.EndPos {
		glog.Infof("[%s] Nothing to do", lw.LogURL)
		if lw.Bar != nil {
			lw.Bar.SetTotal((int64)(lw.EndPos), true)
		}
		return nil
	}

	finalIndex, finalTime, err := lw.downloadCTRangeToChannel(entryChan)
	if err != nil {
		glog.Errorf("[%s] downloadCTRangeToChannel exited with an error: %v, finalIndex=%d, finalTime=%s", lw.LogURL, err, finalIndex, finalTime)
	}

	lw.saveState(finalIndex, finalTime)
	return err
}

func (lw *LogWorker) saveState(index uint64, entryTime *time.Time) {
	if index > 9223372036854775807 {
		glog.Errorf("[%s] Log final index overflows int64. This shouldn't happen: %+v.", lw.LogURL, index)
		return
	}

	lw.LogState.MaxEntry = int64(index)
	if entryTime != nil {
		lw.LogState.LastEntryTime = *entryTime
	}

	defer metrics.MeasureSince([]string{"LogWorker-saveState"}, time.Now())
	glog.Infof("[%s] Saving log state: %s", lw.LogURL, lw.LogState)
	saveErr := lw.Database.SaveLogState(lw.LogState)
	if saveErr != nil {
		glog.Errorf("[%s] Failed to save log state: %s [SaveErr=%s]", lw.LogURL, lw.LogState, saveErr)
		return
	}

	glog.Infof("[%s] Saved log state: %s", lw.LogURL, lw.LogState)
}

// DownloadRange downloads log entries from the given starting index till one
// less than upTo. If status is not nil then status updates will be written to
// it until the function is complete, when it will be closed. The log entries
// are provided to an output channel.
func (lw *LogWorker) downloadCTRangeToChannel(entryChan chan<- CtLogEntry) (uint64, *time.Time, error) {
	ctx := context.Background()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigChan)
	defer close(sigChan)

	var lastTime *time.Time
	var cycleTime time.Time

	index := lw.StartPos
	for index < lw.EndPos {
		max := index + 1024
		if max >= lw.EndPos {
			max = lw.EndPos - 1
		}

		cycleTime = time.Now()

		resp, err := lw.Client.GetRawEntries(ctx, int64(index), int64(max))
		if err != nil {
			return index, lastTime, err
		}
		metrics.MeasureSince([]string{"LogWorker-GetRawEntries"}, cycleTime)

		for _, entry := range resp.Entries {
			index++
			if lw.Bar != nil {
				lw.Bar.IncrBy(1, time.Since(cycleTime))
			}
			cycleTime = time.Now()

			logEntry, err := ct.LogEntryFromLeaf(int64(index), &entry)
			if _, ok := err.(x509.NonFatalErrors); !ok && err != nil {
				glog.Warningf("Erroneous certificate: %v", err)
				continue
			}

			metrics.MeasureSince([]string{"LogWorker-LogEntryFromLeaf"}, cycleTime)

			// Are there waiting signals?
			select {
			case sig := <-sigChan:
				glog.Infof("[%s] Signal caught: %s", lw.LogURL, sig)
				return index, lastTime, nil
			case entryChan <- CtLogEntry{logEntry, lw.LogURL}:
				lastTime = uint64ToTimestamp(logEntry.Leaf.TimestampedEntry.Timestamp)

				lw.Backoff.Reset()
			case <-lw.SaveTicker.C:
				lw.saveState(index, lastTime)
			default:
				// Channel full, retry
				time.Sleep(lw.Backoff.Duration())
			}
		}
	}

	return index, lastTime, nil
}

func main() {
	storageDB, _, _ := engine.GetConfiguredStorage(ctconfig)

	if ctconfig.IssuerCNFilter != nil && len(*ctconfig.IssuerCNFilter) > 0 {
		glog.Infof("IssuerCNFilter is set, but unsupported")
	}

	infoDumpPeriod, err := time.ParseDuration(*ctconfig.StatsRefreshPeriod)
	if err != nil {
		glog.Fatal(err)
	}

	metricsSink := metrics.NewInmemSink(10*time.Second, time.Minute)
	telemetry.NewMetricsDumper(metricsSink, infoDumpPeriod)
	_, err = metrics.NewGlobal(metrics.DefaultConfig("ct-fetch"), metricsSink)
	if err != nil {
		glog.Fatal(err)
	}

	logUrls := []url.URL{}

	if ctconfig.LogUrlList != nil && len(*ctconfig.LogUrlList) > 5 {
		for _, part := range strings.Split(*ctconfig.LogUrlList, ",") {
			ctLogUrl, err := url.Parse(strings.TrimSpace(part))
			if err != nil {
				glog.Fatalf("unable to set Certificate Log: %s", err)
			}
			logUrls = append(logUrls, *ctLogUrl)
		}
	}

	if len(logUrls) > 0 {
		syncEngine := NewLogSyncEngine(storageDB)

		// Start a pool of threads to parse log entries and hand them to the database
		syncEngine.StartDatabaseThreads()

		// Start one thread per CT log to process the log entries
		for _, ctLogUrl := range logUrls {
			urlString := ctLogUrl.String()
			glog.Infof("[%s] Starting download.", urlString)

			syncEngine.DownloaderWaitGroup.Add(1)
			go func() {
				defer syncEngine.DownloaderWaitGroup.Done()

				sigChan := make(chan os.Signal, 1)
				signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
				defer signal.Stop(sigChan)
				defer close(sigChan)

				for {
					err := syncEngine.SyncLog(urlString)
					if err != nil {
						glog.Errorf("[%s] Could not sync log: %s", urlString, err)
					}

					if !*ctconfig.RunForever {
						return
					}

					// Sleep PollingDelay + rand(15) minutes
					timeJitter := time.Duration(rand.Int63n(int64(time.Minute * 15)))
					sleepTime := time.Duration(*ctconfig.PollingDelay)*time.Minute + timeJitter
					glog.Infof("[%s] Stopped. Polling again in %s.", urlString, sleepTime)

					select {
					case <-sigChan:
						glog.Infof("[%s] Signal caught. Exiting.", urlString)
						return
					case <-time.After(sleepTime):
						continue
					}
				}
			}()
		}

		syncEngine.DownloaderWaitGroup.Wait() // Wait for downloaders to stop
		syncEngine.Stop()                     // Stop workers
		syncEngine.ThreadWaitGroup.Wait()     // Wait for workers to stop
		syncEngine.Cleanup()                  // Ensure cache is coherent

		os.Exit(0)
	}

	// Didn't include a mandatory action, so print usage and exit.
	ctconfig.Usage()
	os.Exit(2)
}
