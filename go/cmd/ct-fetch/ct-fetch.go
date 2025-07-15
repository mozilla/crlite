/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// Based on github.com/jcjones/ct-sql/

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/hashicorp/go-metrics"

	"github.com/mozilla/crlite/go"
	"github.com/mozilla/crlite/go/config"
	"github.com/mozilla/crlite/go/engine"
	"github.com/mozilla/crlite/go/storage"
)

var (
	ctconfig   = config.NewCTConfig()
	httpClient = http.Client{
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
	}
	userAgent = "ct-fetch; +https://github.com/mozilla/crlite"
)

type CtLogEntry struct {
	Certificate *x509.Certificate
	Issuer      *x509.Certificate
	Index       int64
	LogMeta     *types.CTLogMetadata
}

// Coordinates all workers
type LogSyncEngine struct {
	ThreadWaitGroup     *sync.WaitGroup
	DownloaderWaitGroup *sync.WaitGroup
	database            storage.CertDatabase
	entryChan           chan CtLogEntry
	lastUpdateTime      time.Time
	lastUpdateMutex     *sync.RWMutex
}

func NewLogSyncEngine(db storage.CertDatabase) *LogSyncEngine {
	return &LogSyncEngine{
		ThreadWaitGroup:     new(sync.WaitGroup),
		DownloaderWaitGroup: new(sync.WaitGroup),
		database:            db,
		entryChan:           make(chan CtLogEntry, 1024*16),
		lastUpdateTime:      time.Time{},
		lastUpdateMutex:     &sync.RWMutex{},
	}
}

func (ld *LogSyncEngine) StartDatabaseThreads() {
	glog.Infof("Starting %d threads...", *ctconfig.NumThreads)
	for t := 0; t < *ctconfig.NumThreads; t++ {
		go ld.insertCTWorker()
	}
}

// Blocking function, run from a thread
func (ld *LogSyncEngine) SyncLog(ctx context.Context, enrolledLogs *EnrolledLogs, logMeta types.CTLogMetadata) error {
	ld.DownloaderWaitGroup.Add(1)
	defer ld.DownloaderWaitGroup.Done()

	if err := ld.database.Migrate(&logMeta); err != nil {
		return err
	}

	// Tiled logs store chains as lists of certificate fingerprints. The
	// certificates themselves need to be fetched from https://<monitoring
	// prefix>/issuer/<fingerprint>. The cache mapping fingerprints to
	// certificates is stored here in SyncLog so that it can persist across
	// many TiledLogWorker jobs.
	issuerMap := map[string]*x509.Certificate{}

	for {
		if !enrolledLogs.IsEnrolled(logMeta.LogID) {
			return nil
		}

		if logMeta.Tiled {
			worker, err := NewTiledLogWorker(ctx, ld.database, &logMeta, &issuerMap)
			if err != nil {
				metrics.IncrCounter([]string{"sync", "error"}, 1)
				return err
			}

			err = worker.Run(ctx, ld.entryChan)
			if err != nil {
				glog.Errorf("[%s] Could not sync log: %s", logMeta.URL, err)
				metrics.IncrCounter([]string{"sync", "error"}, 1)
				return err
			}
		} else {
			worker, err := NewLogWorker(ctx, ld.database, &logMeta)
			if err != nil {
				metrics.IncrCounter([]string{"sync", "error"}, 1)
				return err
			}

			err = worker.Run(ctx, ld.entryChan)
			if err != nil {
				glog.Errorf("[%s] Could not sync log: %s", logMeta.URL, err)
				metrics.IncrCounter([]string{"sync", "error"}, 1)
				return err
			}
		}

		// We did useful work. Register an update for the health service.
		ld.RegisterUpdate()

		if !*ctconfig.RunForever {
			return nil
		}

		select {
		case <-ctx.Done():
			glog.Infof("[%s] Downloader exiting.", logMeta.URL)
			return nil
		default:
		}
	}
}

func (ld *LogSyncEngine) RegisterUpdate() {
	metrics.IncrCounter([]string{"sync", "progress"}, 1)
	ld.lastUpdateMutex.Lock()
	defer ld.lastUpdateMutex.Unlock()
	ld.lastUpdateTime = time.Now()
}

func (ld *LogSyncEngine) ApproximateMostRecentUpdateTimestamp() time.Time {
	ld.lastUpdateMutex.RLock()
	defer ld.lastUpdateMutex.RUnlock()
	return ld.lastUpdateTime
}

func (ld *LogSyncEngine) Wait() {
	// Wait for the CT Log downloaders to finish. If we're configured
	// to run forever, then this only happens if there are no enrolled logs,
	// or if all downloaders have encountered an error, or if the main thread's
	// cancel function has been called.
	ld.DownloaderWaitGroup.Wait()

	// No more log entries will be downloaded.
	close(ld.entryChan)

	// Finish handling |ld.entryChan|
	glog.Infof("Waiting on database writes to complete: %d remaining", len(ld.entryChan))
	ld.ThreadWaitGroup.Wait()
}

func (ld *LogSyncEngine) insertCTWorker() {
	ld.ThreadWaitGroup.Add(1)
	defer ld.ThreadWaitGroup.Done()

	healthStatusPeriod, _ := time.ParseDuration("15s")
	healthStatusJitter := rand.Int63n(15 * 1000)
	healthStatusDuration := healthStatusPeriod + time.Duration(healthStatusJitter)*time.Millisecond
	glog.Infof("Thread health status period: %v + %v = %v", healthStatusPeriod, healthStatusJitter, healthStatusDuration)
	healthStatusTicker := time.NewTicker(healthStatusDuration)
	defer healthStatusTicker.Stop()

	for ep := range ld.entryChan {
		select { // Taking something off the queue is useful work.
		// So indicate server health when requested.
		case <-healthStatusTicker.C:
			ld.RegisterUpdate()
		default:
		}

		err := ld.database.Store(ep.Certificate, ep.Issuer)
		if err != nil {
			glog.Errorf("[%s] Problem inserting certificate: index: %d error: %s", ep.LogMeta.URL, ep.Index, err)
		}
	}
}

type LogWorkerTask int

const (
	Init        LogWorkerTask = iota // Initialize db with one batch of recent certs
	Backfill                         // Download old certs
	Update                           // Download new certs
	ForceUpdate                      // Download new certs even if doing so will fetch a partial tile
	Sleep                            // Wait for an STH update
)

type EnrolledLogs struct {
	wg       *sync.WaitGroup
	mutex    *sync.RWMutex
	metadata map[string]types.CTLogMetadata
	NewChan  chan types.CTLogMetadata
}

func NewEnrolledLogs() *EnrolledLogs {
	wg := new(sync.WaitGroup)
	wg.Add(1)

	return &EnrolledLogs{
		wg:       wg,
		mutex:    new(sync.RWMutex),
		metadata: make(map[string]types.CTLogMetadata),
		NewChan:  make(chan types.CTLogMetadata),
	}
}

func (el *EnrolledLogs) Finalize() {
	el.wg.Done()
	close(el.NewChan)
}

func (el *EnrolledLogs) Wait() {
	el.wg.Wait()
}

func (el *EnrolledLogs) Count() int {
	el.mutex.RLock()
	defer el.mutex.RUnlock()

	return len(el.metadata)
}

func (el *EnrolledLogs) Enroll(ctLog types.CTLogMetadata) {
	el.mutex.Lock()
	defer el.mutex.Unlock()

	_, prs := el.metadata[ctLog.LogID]
	if !prs {
		el.metadata[ctLog.LogID] = ctLog
		el.NewChan <- ctLog
	}
}

func (el *EnrolledLogs) Unenroll(ctLog types.CTLogMetadata) {
	el.mutex.Lock()
	defer el.mutex.Unlock()

	delete(el.metadata, ctLog.LogID)
}

func (el *EnrolledLogs) IsEnrolled(logID string) bool {
	el.mutex.RLock()
	defer el.mutex.RUnlock()

	_, prs := el.metadata[logID]
	return prs
}

func (el *EnrolledLogs) updateFromRemoteSettingsOnce() error {
	remoteSettingsURL, err := url.Parse(*ctconfig.RemoteSettingsURL)
	if err != nil {
		return err
	}

	if remoteSettingsURL.Scheme != "https" {
		glog.Warning("Changing RemoteSettingsURL scheme to https")
		remoteSettingsURL.Scheme = "https"
	}

	ctLogConfURL, _ := remoteSettingsURL.Parse(
		"buckets/security-state/collections/ct-logs/records")

	httpRsp, err := httpClient.Get(ctLogConfURL.String())
	if err != nil {
		return err
	}

	body, err := ioutil.ReadAll(httpRsp.Body)
	httpRsp.Body.Close()
	if err != nil {
		return err
	}

	if httpRsp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP Status %q", httpRsp.Status)
	}

	// The response from the remote settings server is
	// { "data" : []CTLogMetadata }
	var ctLogJSON map[string][]types.CTLogMetadata

	if err := json.Unmarshal([]byte(body), &ctLogJSON); err != nil {
		return err
	}

	_, exists := ctLogJSON["data"]
	if !exists {
		return fmt.Errorf("Malformed response from Remote Settings %s", *ctconfig.RemoteSettingsURL)
	}

	el.mutex.Lock()
	defer el.mutex.Unlock()
	for _, ctLog := range ctLogJSON["data"] {
		_, prs := el.metadata[ctLog.LogID]
		if prs {
			if !ctLog.CRLiteEnrolled {
				delete(el.metadata, ctLog.LogID)
				glog.Infof("[%s] Unenrolled", ctLog.URL)
			} else {
				glog.Infof("[%s] Remains enrolled", ctLog.URL)
			}
		} else {
			if ctLog.CRLiteEnrolled {
				el.metadata[ctLog.LogID] = ctLog
				el.NewChan <- ctLog
				glog.Infof("[%s] Enrolled with LogID %s", ctLog.URL, ctLog.LogID)
			}
		}
	}

	return nil
}

func (el *EnrolledLogs) UpdateFromRemoteSettings(ctx context.Context) {
	defer el.Finalize()
	for {
		glog.Infof("Updating Enrolled CT log list from remote settings.")
		err := el.updateFromRemoteSettingsOnce()
		if err != nil {
			glog.Errorf("Unable to get enrolled logs from Remote Settings: %s", err)
		}
		if !*ctconfig.RunForever {
			return
		}
		glog.Infof("There are %d logs enrolled. Polling again in %d seconds.", el.Count(), *ctconfig.RemoteSettingsUpdateInterval)
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Duration(*ctconfig.RemoteSettingsUpdateInterval) * time.Second):
		}
	}
}

func main() {
	defer glog.Flush()

	ctconfig.Init()

	ctx := context.Background()
	ctx, cancelMain := context.WithCancel(ctx)

	// Try to handle SIGINT and SIGTERM gracefully
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	defer close(sigChan)
	go func() {
		sig := <-sigChan
		glog.Infof("Signal caught: %s..", sig)
		cancelMain()
		signal.Stop(sigChan) // Restore default behavior
	}()

	// Seed random for clock jitter
	rand.Seed(time.Now().UnixNano())

	storageDB, _ := engine.GetConfiguredStorage(ctx, ctconfig, true)
	err := storageDB.EnsureCacheIsConsistent()
	if err != nil {
		glog.Errorf("Could not recover cache: %s", err)
		os.Exit(1)
	}

	engine.PrepareTelemetry("ct-fetch", ctconfig)

	enrolledLogs := NewEnrolledLogs()

	syncEngine := NewLogSyncEngine(storageDB)

	// Start a pool of threads to parse and store log entries
	syncEngine.StartDatabaseThreads()

	// Sync with logs as they are enrolled
	go func() {
		for ctLog := range enrolledLogs.NewChan {
			glog.Infof("[%s] Starting download.", ctLog.URL)
			go syncEngine.SyncLog(ctx, enrolledLogs, ctLog)
		}
	}()

	// Enroll logs from local settings
	if *ctconfig.CTLogMetadata != "" {
		localCTLogList := new([]types.CTLogMetadata)
		if err := json.Unmarshal([]byte(*ctconfig.CTLogMetadata), localCTLogList); err != nil {
			glog.Fatalf("Unable to parse CTLogMetadata argument: %s", err)
		}

		for _, ctLog := range *localCTLogList {
			if ctLog.CRLiteEnrolled {
				enrolledLogs.Enroll(ctLog)
			}
		}
	}

	if enrolledLogs.Count() == 0 && *ctconfig.RemoteSettingsURL == "" {
		// Didn't include a mandatory action, so print usage and exit.
		if *ctconfig.CTLogMetadata != "" {
			glog.Warningf("No enrolled logs found in %s.", *ctconfig.CTLogMetadata)
		}
		ctconfig.Usage()
		os.Exit(2)
	}

	// If we're configured with a Remote Settings URL, we'll periodically look for
	// newly enrolled logs in Remote Settings. Otherwise we have all of the logs already.
	if *ctconfig.RemoteSettingsURL != "" {
		go enrolledLogs.UpdateFromRemoteSettings(ctx)
	} else {
		enrolledLogs.Finalize()
	}

	healthHandler := http.NewServeMux()
	healthHandler.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		approxUpdateTimestamp := syncEngine.ApproximateMostRecentUpdateTimestamp()

		if approxUpdateTimestamp.IsZero() {
			w.Header().Add("Retry-After", "30")
			w.WriteHeader(503)
			_, err := w.Write([]byte("error: no health updates yet, Retry-After 30 seconds"))
			if err != nil {
				glog.Warningf("Couldn't return too early health status: %+v", err)
			}
			return
		}

		duration := time.Since(approxUpdateTimestamp)
		evaluationTime := 2 * time.Duration(*ctconfig.PollingDelay) * time.Second
		if duration > evaluationTime {
			w.WriteHeader(500)
			_, err := w.Write([]byte(fmt.Sprintf("error: %v since last update, which is longer than 2 * pollingDelay", duration)))
			if err != nil {
				glog.Warningf("Couldn't return poor health status: %+v", err)
			}
			return
		}

		w.WriteHeader(200)
		_, err := w.Write([]byte(fmt.Sprintf("ok: %v since last update, which is shorter than 2 * pollingDelay", duration)))
		if err != nil {
			glog.Warningf("Couldn't return ok health status: %+v", err)
		}
	})

	healthServer := &http.Server{
		Handler: healthHandler,
		Addr:    *ctconfig.HealthAddr,
	}
	go healthServer.ListenAndServe()

	// Wait until we've finalized enrollment.
	enrolledLogs.Wait()

	// Wait until all jobs are finished.
	syncEngine.Wait()

	if err := healthServer.Shutdown(ctx); err != nil {
		glog.Infof("HTTP server shutdown error: %v", err)
	}
	glog.Flush()

	os.Exit(0)
}
