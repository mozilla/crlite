/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// Based on github.com/jcjones/ct-sql/

package main

import (
	"fmt"
	"github.com/golang/glog"
	"golang.org/x/net/context"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/jcjones/ct-mapreduce/config"
	"github.com/jcjones/ct-mapreduce/storage"
	"github.com/jpillora/backoff"
	"gopkg.in/cheggaaa/pb.v1"
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

	// if skip && edb.Verbose {
	//  fmt.Printf("Skipping inserting cert issued by %s\n", cert.Issuer.CommonName)
	// }

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
type LogDownloader struct {
	Database            storage.CertDatabase
	EntryChan           chan CtLogEntry
	ThreadWaitGroup     *sync.WaitGroup
	DownloaderWaitGroup *sync.WaitGroup
}

// Operates on a single log
type LogWorker struct {
	Display  *pb.ProgressBar
	Database storage.CertDatabase
	Client   *client.LogClient
	LogURL   string
	STH      *ct.SignedTreeHead
	LogState *storage.CertificateLog
	StartPos uint64
	EndPos   uint64
	Backoff  *backoff.Backoff
}

func NewLogWorker(db storage.CertDatabase, ctLogUrl string) (*LogWorker, error) {
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
	urlParts, err := url.Parse(ctLogUrl)
	if err != nil {
		glog.Errorf("[%s] Unable to parse Certificate Log: %s", ctLogUrl, err)
		return nil, err
	}
	logObj, err := db.GetLogState(fmt.Sprintf("%s%s", urlParts.Host, urlParts.Path))
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
		startPos = logObj.MaxEntry
		if err != nil {
			glog.Errorf("[%s] Failed to read entries file: %s", ctLogUrl, err)
			return nil, err
		}
	}

	var endPos uint64
	endPos = sth.TreeSize
	if *ctconfig.Limit > 0 && (startPos+*ctconfig.Limit) < sth.TreeSize {
		endPos = startPos + *ctconfig.Limit
	}

	glog.Infof("[%s] %d total entries as of %s\n", ctLogUrl, sth.TreeSize, uint64ToTimestamp(sth.Timestamp).Format(time.ANSIC))
	// if origCount == sth.TreeSize {
	// 	glog.Infof("[%s] Nothing to do\n", ctLogUrl)
	// 	return nil, nil
	// }

	return &LogWorker{
		Display:  nil,
		Database: db,
		Client:   ctLog,
		LogState: logObj,
		LogURL:   ctLogUrl,
		STH:      sth,
		StartPos: startPos,
		EndPos:   endPos,
		Backoff: &backoff.Backoff{
			Min:    10 * time.Millisecond,
			Max:    1 * time.Second,
			Jitter: true,
		},
	}, nil
}

func NewLogDownloader(db storage.CertDatabase) *LogDownloader {
	return &LogDownloader{
		Database:            db,
		EntryChan:           make(chan CtLogEntry, 1024),
		ThreadWaitGroup:     new(sync.WaitGroup),
		DownloaderWaitGroup: new(sync.WaitGroup),
	}
}

func (ld *LogDownloader) StartThreads() {
	for t := 0; t < *ctconfig.NumThreads; t++ {
		go ld.insertCTWorker()
	}
}

// Blocking function, run from a thread
func (ld *LogDownloader) SyncLog(logURL string) error {
	worker, err := NewLogWorker(ld.Database, logURL)
	if err != nil {
		return err
	}
	return worker.SyncLog(ld.EntryChan)
}

func (ld *LogDownloader) Stop() {
	close(ld.EntryChan)
	// ld.Display.Finish()
}

func (ld *LogDownloader) Cleanup() {
	err := ld.Database.Cleanup()
	if err != nil {
		glog.Errorf("\nCache cleanup error caught: %s", err)
	}
}

func (lw *LogWorker) SyncLog(entryChan chan<- CtLogEntry) error {
	glog.Infof("[%s] Going from %d to %d (%4.2f%% complete to head of log)\n", lw.LogURL, lw.StartPos, lw.EndPos, float64(lw.StartPos)/float64(lw.STH.TreeSize)*100)

	// lw.Display = pb.New(endPos - origCount).Prefix(fmt.Sprintf("%s", ctLogUrl))

	finalIndex, finalTime, err := lw.downloadCTRangeToChannel(entryChan)
	if err != nil {
		glog.Errorf("\n[%s] Download halting, error caught: %s\n", lw.LogURL, err)
		return err
	}

	lw.LogState.MaxEntry = finalIndex
	if finalTime != nil {
		lw.LogState.LastEntryTime = *finalTime
	}

	err = lw.Database.SaveLogState(lw.LogState)
	if err != nil {
		glog.Errorf("[%s] Log state save failed, %s Err=%s, Err=%s", lw.LogURL, lw.LogState, err)
		return err
	}

	glog.Infof("[%s] Saved state. %s", lw.LogURL, lw.LogState)
	return nil
}

// DownloadRange downloads log entries from the given starting index till one
// less than upTo. If status is not nil then status updates will be written to
// it until the function is complete, when it will be closed. The log entries
// are provided to an output channel.
func (lw *LogWorker) downloadCTRangeToChannel(entryChan chan<- CtLogEntry) (uint64, *time.Time, error) {
	ctx := context.Background()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, os.Interrupt)
	defer signal.Stop(sigChan)
	defer close(sigChan)

	var lastTime *time.Time

	index := lw.StartPos
	for index < lw.EndPos {
		max := index + 1024
		if max >= lw.EndPos {
			max = lw.EndPos - 1
		}

		resp, err := lw.Client.GetRawEntries(ctx, int64(index), int64(max))
		if err != nil {
			return index, lastTime, err
		}

		for _, entry := range resp.Entries {
			index++
			// ld.Display.Increment()
			logEntry, err := ct.LogEntryFromLeaf(int64(index), &entry)
			if _, ok := err.(x509.NonFatalErrors); !ok && err != nil {
				fmt.Printf("Erroneous certificate: %v\n", err)
				continue
			}

			// Are there waiting signals?
			select {
			case sig := <-sigChan:
				return index, lastTime, fmt.Errorf("Signal caught: %s", sig)
			case entryChan <- CtLogEntry{logEntry, lw.LogURL}:
				lastTime = uint64ToTimestamp(logEntry.Leaf.TimestampedEntry.Timestamp)

				lw.Backoff.Reset()
			default:
				// Channel full, retry
				time.Sleep(lw.Backoff.Duration())
			}
		}
	}

	return index, lastTime, nil
}

func (ld *LogDownloader) insertCTWorker() {
	ld.ThreadWaitGroup.Add(1)
	defer ld.ThreadWaitGroup.Done()
	for ep := range ld.EntryChan {
		var cert *x509.Certificate
		var err error

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

		err = ld.Database.Store(cert, ep.LogURL)
		if err != nil {
			glog.Errorf("Problem inserting certificate: index: %d error: %s", ep.LogEntry.Index, err)
		}
	}
}

func main() {
	var err error
	var storageDB storage.CertDatabase
	if ctconfig.CertPath != nil && len(*ctconfig.CertPath) > 0 {
		glog.Infof("Saving to disk at %s", *ctconfig.CertPath)
		storageDB, err = storage.NewDiskDatabase(*ctconfig.CacheSize, *ctconfig.CertPath, 0644)
		if err != nil {
			glog.Fatalf("unable to open Certificate Path: %s: %s", ctconfig.CertPath, err)
		}
	}

	if storageDB == nil {
		ctconfig.Usage()
		os.Exit(2)
	}

	var issuerCNList []string
	if ctconfig.IssuerCNFilter != nil && len(*ctconfig.IssuerCNFilter) > 0 {
		for _, part := range strings.Split(*ctconfig.IssuerCNFilter, ",") {
			cnFilter := strings.TrimSpace(part)
			if len(cnFilter) > 0 {
				issuerCNList = append(issuerCNList, cnFilter)
			}
		}
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
		logDownloader := NewLogDownloader(storageDB)
		// logDownloader.Display.StartDisplay(logDownloader.ThreadWaitGroup)
		// Start a pool of threads to parse log entries and hand them to the database
		logDownloader.StartThreads()

		// Start one thread per CT log to process the log entries
		for _, ctLogUrl := range logUrls {
			urlString := ctLogUrl.String()
			glog.Infof("[%s] Starting download.\n", urlString)

			logDownloader.DownloaderWaitGroup.Add(1)
			go func() {
				defer logDownloader.DownloaderWaitGroup.Done()

				sigChan := make(chan os.Signal, 1)
				signal.Notify(sigChan, syscall.SIGTERM, os.Interrupt)
				defer signal.Stop(sigChan)
				defer close(sigChan)

				for {
					err := logDownloader.SyncLog(urlString)
					if err != nil {
						glog.Errorf("[%s] Could not sync log: %s", urlString, err)
					}

					if !*ctconfig.RunForever {
						return
					}
					sleepTime := time.Duration(*ctconfig.PollingDelay) * time.Minute
					glog.Infof("[%s] Stopped. Polling again in %s.\n", urlString, sleepTime)

					select {
					case <-sigChan:
						glog.Infof("[%s] Signal caught.\n", urlString)
						return
					case <-time.After(sleepTime):
						continue
					}
				}
			}()
		}

		logDownloader.DownloaderWaitGroup.Wait() // Wait for downloaders to stop
		logDownloader.Stop()                     // Stop workers
		logDownloader.ThreadWaitGroup.Wait()     // Wait for workers to stop
		logDownloader.Cleanup()                  // Ensure cache is coherent

		os.Exit(0)
	}

	// Didn't include a mandatory action, so print usage and exit.
	ctconfig.Usage()
	os.Exit(2)
}
