/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// Based on github.com/jcjones/ct-sql/

package main

import (
	"context"
	"math"
	"math/rand"
	"net/http"
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
	"github.com/jpillora/backoff"
	"github.com/vbauerster/mpb/v5"
	"github.com/vbauerster/mpb/v5/decor"
)

var (
	ctconfig = config.NewCTConfig()
)

func certIsFilteredOut(aCert *x509.Certificate) bool {
	// Skip unimportant entries, if configured

	if aCert.BasicConstraintsValid && aCert.IsCA {
		metrics.IncrCounter([]string{"certIsFilteredOut", "CA"}, 1)
		return true
	}

	if aCert.NotAfter.Before(time.Now()) && !*ctconfig.LogExpiredEntries {
		metrics.IncrCounter([]string{"certIsFilteredOut", "expired"}, 1)
		return true
	}

	skip := (len(*ctconfig.IssuerCNFilter) != 0)
	for _, filter := range strings.Split(*ctconfig.IssuerCNFilter, ",") {
		if strings.HasPrefix(aCert.Issuer.CommonName, filter) {
			skip = false
			break
		}
	}

	if skip {
		metrics.IncrCounter([]string{"certIsFilteredOut", "cn-filtered"}, 1)
		glog.V(4).Infof("Skipping inserting cert issued by %s", aCert.Issuer.CommonName)
	}
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
	display             *mpb.Progress
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
}

func NewLogSyncEngine(db storage.CertDatabase) *LogSyncEngine {
	ctx, cancel := context.WithCancel(context.Background())
	twg := new(sync.WaitGroup)

	refreshDur, err := time.ParseDuration(*ctconfig.OutputRefreshPeriod)
	if err != nil {
		glog.Fatal(err)
	}
	glog.Infof("Progress bar refresh rate is every %s.\n", refreshDur.String())

	display := mpb.NewWithContext(ctx,
		mpb.WithWaitGroup(twg),
		mpb.WithRefreshRate(refreshDur),
	)

	return &LogSyncEngine{
		ThreadWaitGroup:     twg,
		DownloaderWaitGroup: new(sync.WaitGroup),
		database:            db,
		entryChan:           make(chan CtLogEntry, 1024*16),
		display:             display,
		cancelTrigger:       cancel,
	}
}

func (ld *LogSyncEngine) StartDatabaseThreads() {
	glog.Infof("Starting %d threads...", *ctconfig.NumThreads)
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

func (ld *LogSyncEngine) ApproximateRemainingEntries() int {
	return len(ld.entryChan)
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
		precert := false

		parseTime := time.Now()

		switch ep.LogEntry.Leaf.TimestampedEntry.EntryType {
		case ct.X509LogEntryType:
			cert = ep.LogEntry.X509Cert
		case ct.PrecertLogEntryType:
			cert, err = x509.ParseCertificate(ep.LogEntry.Precert.Submitted.Data)
			precert = true
		}

		if err != nil {
			glog.Errorf("[%s] Problem decoding certificate: index: %d error: %s", ep.LogURL, ep.LogEntry.Index, err)
			continue
		}

		if certIsFilteredOut(cert) {
			continue
		}

		if len(ep.LogEntry.Chain) < 1 {
			glog.Warningf("[%s] No issuer known for certificate precert=%v index=%d serial=%s subject=%+v issuer=%+v",
				ep.LogURL, precert, ep.LogEntry.Index, storage.NewSerial(cert).String(), cert.Subject, cert.Issuer)
			continue
		}

		issuingCert, err := x509.ParseCertificate(ep.LogEntry.Chain[0].Data)
		if err != nil {
			glog.Errorf("[%s] Problem decoding issuing certificate: index: %d error: %s", ep.LogURL, ep.LogEntry.Index, err)
			continue
		}
		metrics.MeasureSince([]string{"insertCTWorker", "ParseCertificates"}, parseTime)

		storeTime := time.Now()
		err = ld.database.Store(cert, issuingCert, ep.LogURL, ep.LogEntry.Index)
		if err != nil {
			glog.Errorf("[%s] Problem inserting certificate: index: %d error: %s", ep.LogURL, ep.LogEntry.Index, err)
		}
		metrics.MeasureSince([]string{"insertCTWorker", "Store"}, storeTime)
	}
}

func (ld *LogSyncEngine) NewLogWorker(ctLogUrl string) (*LogWorker, error) {
	ctLog, err := client.New(ctLogUrl,
		&http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSHandshakeTimeout:   30 * time.Second,
				ResponseHeaderTimeout: 30 * time.Second,
				MaxIdleConnsPerHost:   10,
				DisableKeepAlives:     false,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			},
		}, jsonclient.Options{
			UserAgent: "ct-mapreduce; https://github.com/jcjones/ct-mapreduce",
		})
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

	glog.Infof("[%s] %d total entries as of %s", ctLogUrl, sth.TreeSize,
		uint64ToTimestamp(sth.Timestamp).Format(time.ANSIC))

	progressBar := ld.display.AddBar((int64)(endPos-startPos),
		mpb.PrependDecorators(
			// display our name with one space on the right
			decor.Name(logObj.ShortURL, decor.WC{W: 30, C: decor.DidentRight}),
		),
		mpb.AppendDecorators(
			decor.Percentage(),
			decor.Name(""),
			decor.AverageETA(decor.ET_STYLE_GO, decor.WC{W: 14}),
			decor.AverageSpeed(0, "%.1f/s", decor.WC{W: 10}),
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
	}, nil
}

func (lw *LogWorker) Run(entryChan chan<- CtLogEntry) error {
	defer lw.SaveTicker.Stop()

	glog.Infof("[%s] Going from %d to %d (%4.2f%% complete to head of log)",
		lw.LogURL, lw.StartPos, lw.EndPos,
		float64(lw.StartPos)/float64(lw.STH.TreeSize)*100)

	if lw.StartPos == lw.EndPos {
		glog.Infof("[%s] Nothing to do", lw.LogURL)
		if lw.Bar != nil {
			lw.Bar.SetTotal((int64)(lw.EndPos), true)
		}
		return nil
	}

	finalIndex, finalTime, err := lw.downloadCTRangeToChannel(entryChan)
	if err != nil {
		lw.Bar.Abort(true)
		glog.Errorf("[%s] downloadCTRangeToChannel exited with an error: %v, finalIndex=%d, finalTime=%s",
			lw.LogURL, err, finalIndex, finalTime)
	}

	lw.saveState(finalIndex, finalTime)
	return err
}

func (lw *LogWorker) saveState(index uint64, entryTime *time.Time) {
	if index > math.MaxInt64 {
		glog.Errorf("[%s] Log final index overflows int64. This shouldn't happen: %+v.",
			lw.LogURL, index)
		return
	}

	lw.LogState.MaxEntry = int64(index)
	if entryTime != nil {
		lw.LogState.LastEntryTime = *entryTime
	}

	defer metrics.MeasureSince([]string{"LogWorker", "saveState"}, time.Now())
	saveErr := lw.Database.SaveLogState(lw.LogState)
	if saveErr != nil {
		glog.Errorf("[%s] Failed to save log state: %s [SaveErr=%s]", lw.LogURL, lw.LogState, saveErr)
		return
	}

	glog.V(1).Infof("[%s] Saved log state: %s", lw.LogURL, lw.LogState)
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

	var lastEntryTimestamp *time.Time
	var cycleTime time.Time

	b := &backoff.Backoff{
		Jitter: true,
		Min:    500 * time.Millisecond,
		Max:    5 * time.Minute,
	}

	index := lw.StartPos
	for index < lw.EndPos {
		max := index + 1000
		if max >= lw.EndPos {
			max = lw.EndPos - 1
		}

		cycleTime = time.Now()

		resp, err := lw.Client.GetRawEntries(ctx, int64(index), int64(max))
		if err != nil {
			if strings.Contains(err.Error(), "HTTP Status") &&
				(strings.Contains(err.Error(), "429") || strings.Contains(err.Error(), "Too Many Requests")) {
				d := b.Duration()
				glog.Infof("[%s] received status code 429 at index=%d, retrying in %s: %v", lw.LogURL, index, d, err)

				metrics.IncrCounter([]string{"LogWorker", "429 Too Many Requests"}, 1)
				metrics.AddSample([]string{"LogWorker", "429 Too Many Requests", "Backoff"},
					float32(d))

				time.Sleep(d)
				continue
			}

			glog.Warningf("Failed to get entries: %v", err)
			metrics.IncrCounter([]string{"LogWorker", "GetRawEntries", "error"}, 1)
			return index, lastEntryTimestamp, err
		}
		metrics.MeasureSince([]string{"LogWorker", "GetRawEntries"}, cycleTime)
		b.Reset()

		for _, entry := range resp.Entries {
			if lw.Bar != nil {
				lw.Bar.IncrBy(1)
			}
			cycleTime = time.Now()

			logEntry, err := ct.LogEntryFromLeaf(int64(index), &entry)
			if _, ok := err.(x509.NonFatalErrors); !ok && err != nil {
				glog.Warningf("Erroneous certificate: log=%s index=%d err=%v",
					lw.LogURL, index, err)

				metrics.IncrCounter([]string{"LogWorker", "downloadCTRangeToChannel", "error"}, 1)
				index++
				continue
			}

			metrics.MeasureSince([]string{"LogWorker", "LogEntryFromLeaf"}, cycleTime)

			// Are there waiting signals?
			submitToChannelTime := time.Now()
		entrySavedLoop:
			for {
				select {
				case sig := <-sigChan:
					glog.Infof("[%s] Signal caught: %s, at %d time %v", lw.LogURL, sig, index, lastEntryTimestamp)
					return index, lastEntryTimestamp, nil
				case <-lw.SaveTicker.C:
					lw.saveState(index, lastEntryTimestamp)
					// continue trying to store logEntry
				case entryChan <- CtLogEntry{logEntry, lw.LogURL}:
					lastEntryTimestamp = uint64ToTimestamp(logEntry.Leaf.TimestampedEntry.Timestamp)
					metrics.MeasureSince([]string{"LogWorker", "SubmittedToChannel"}, submitToChannelTime)
					break entrySavedLoop // proceed
				}
			}

			metrics.MeasureSince([]string{"LogWorker", "ProcessedEntry"}, cycleTime)
			index++
		}
	}

	return index, lastEntryTimestamp, nil
}

func main() {
	ctconfig.Init()
	ctx := context.Background()

	storageDB, _, _ := engine.GetConfiguredStorage(ctx, ctconfig)
	defer glog.Flush()

	if ctconfig.IssuerCNFilter != nil && len(*ctconfig.IssuerCNFilter) > 0 {
		glog.Infof("IssuerCNFilter is set, but unsupported")
	}

	engine.PrepareTelemetry("ct-fetch", ctconfig)

	pollingDelayMean, err := time.ParseDuration(*ctconfig.PollingDelayMean)
	if err != nil {
		glog.Fatalf("Could not parse PollingDelayMean: %v", err)
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

					sampledSeconds := rand.NormFloat64() * float64(*ctconfig.PollingDelayStdDev)
					sleepTime := time.Duration(sampledSeconds)*time.Second + pollingDelayMean
					glog.Infof("[%s] Stopped. Polling again in %v. stddev=%v", urlString,
						sleepTime, *ctconfig.PollingDelayStdDev)

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
		go func() {
			for {
				glog.Infof("Waiting on database writes to complete: %d remaining",
					syncEngine.ApproximateRemainingEntries())
				time.Sleep(time.Second)
			}
		}()
		syncEngine.Stop()                 // Stop workers
		syncEngine.ThreadWaitGroup.Wait() // Wait for workers to stop
		syncEngine.Cleanup()              // Ensure cache is coherent
		glog.Flush()

		os.Exit(0)
	}

	// Didn't include a mandatory action, so print usage and exit.
	if ctconfig.LogUrlList != nil {
		glog.Warningf("No log URLs found in %s.", *ctconfig.LogUrlList)
	} else {
		glog.Warning("No log URLs provided.")
	}
	ctconfig.Usage()
	os.Exit(2)
}
