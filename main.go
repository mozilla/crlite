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
	"github.com/jcjones/go-progressdisplay"
	"github.com/jpillora/backoff"
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

func uint64ToTimestamp(timestamp uint64) time.Time {
	return time.Unix(int64(timestamp/1000), int64(timestamp%1000))
}

type CtLogEntry struct {
	LogEntry *ct.LogEntry
	LogURL   string
}

type LogDownloader struct {
	Database            storage.CertDatabase
	EntryChan           chan CtLogEntry
	Display             *utils.ProgressDisplay
	ThreadWaitGroup     *sync.WaitGroup
	DownloaderWaitGroup *sync.WaitGroup
	Backoff             *backoff.Backoff
}

func NewLogDownloader(db storage.CertDatabase) *LogDownloader {
	return &LogDownloader{
		Database:            db,
		EntryChan:           make(chan CtLogEntry, 1024),
		Display:             utils.NewProgressDisplay(),
		ThreadWaitGroup:     new(sync.WaitGroup),
		DownloaderWaitGroup: new(sync.WaitGroup),
		Backoff: &backoff.Backoff{
			Min:    10 * time.Millisecond,
			Max:    1 * time.Second,
			Jitter: true,
		},
	}
}

func (ld *LogDownloader) StartThreads() {
	for t := 0; t < *ctconfig.NumThreads; t++ {
		go ld.insertCTWorker()
	}
}

func (ld *LogDownloader) Stop() {
	close(ld.EntryChan)
	ld.Display.Close()
}

func (ld *LogDownloader) Cleanup() {
	err := ld.Database.Cleanup()
	if err != nil {
		glog.Errorf("\nCache cleanup error caught: %s", err)
	}
}

func (ld *LogDownloader) Download(ctLogUrl string) {
	ctLog, err := client.New(ctLogUrl, nil, jsonclient.Options{})
	if err != nil {
		glog.Errorf("[%s] Unable to construct CT log client: %s", ctLogUrl, err)
		return
	}

	glog.Infof("[%s] Fetching signed tree head... ", ctLogUrl)
	sth, err := ctLog.GetSTH(context.Background())
	if err != nil {
		glog.Errorf("[%s] Unable to fetch signed tree head: %s", ctLogUrl, err)
		return
	}

	// Set pointer in DB, now that we've verified the log works
	urlParts, err := url.Parse(ctLogUrl)
	if err != nil {
		glog.Errorf("[%s] Unable to parse Certificate Log: %s", ctLogUrl, err)
		return
	}
	logObj, err := ld.Database.GetLogState(fmt.Sprintf("%s%s", urlParts.Host, urlParts.Path))
	if err != nil {
		glog.Errorf("[%s] Unable to set Certificate Log: %s", ctLogUrl, err)
		return
	}

	var origCount uint64
	// Now we're OK to use the DB
	if *ctconfig.Offset > 0 {
		glog.Infof("[%s] Starting from offset %d", ctLogUrl, *ctconfig.Offset)
		origCount = *ctconfig.Offset
	} else {
		glog.Infof("[%s] Counting existing entries... ", ctLogUrl)
		origCount = logObj.MaxEntry
		if err != nil {
			glog.Errorf("[%s] Failed to read entries file: %s", ctLogUrl, err)
			return
		}
	}

	glog.Infof("[%s] %d total entries at %s\n", ctLogUrl, sth.TreeSize, uint64ToTimestamp(sth.Timestamp).Format(time.ANSIC))
	if origCount == sth.TreeSize {
		glog.Infof("[%s] Nothing to do\n", ctLogUrl)
		return
	}

	endPos := sth.TreeSize
	if *ctconfig.Limit > 0 && endPos > origCount+*ctconfig.Limit {
		endPos = origCount + *ctconfig.Limit
	}

	glog.Infof("[%s] Going from %d to %d (%4.2f%% complete to head of log)\n", ctLogUrl, origCount, endPos, float64(origCount)/float64(sth.TreeSize)*100)

	finalIndex, finalTime, err := ld.downloadCTRangeToChannel(logObj, ctLog, origCount, endPos)
	if err != nil {
		glog.Errorf("\n[%s] Download halting, error caught: %s\n", ctLogUrl, err)
	}

	logObj.MaxEntry = finalIndex
	if finalTime != 0 {
		logObj.LastEntryTime = uint64ToTimestamp(finalTime)
	}

	err = ld.Database.SaveLogState(logObj)
	if err == nil {
		glog.Infof("[%s] Saved state. MaxEntry=%d, LastEntryTime=%s", logObj.URL, logObj.MaxEntry, logObj.LastEntryTime)
	} else {
		glog.Errorf("[%s] Log state save failed, MaxEntry=%d, LastEntryTime=%s, Err=%s", logObj.URL, logObj.MaxEntry, logObj.LastEntryTime, err)
	}
}

// DownloadRange downloads log entries from the given starting index till one
// less than upTo. If status is not nil then status updates will be written to
// it until the function is complete, when it will be closed. The log entries
// are provided to an output channel.
func (ld *LogDownloader) downloadCTRangeToChannel(log *storage.CertificateLog, ctLog *client.LogClient, start, upTo uint64) (uint64, uint64, error) {
	ctx := context.Background()

	if ld.EntryChan == nil {
		return start, 0, fmt.Errorf("No output channel provided")
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, os.Interrupt)
	defer signal.Stop(sigChan)
	defer close(sigChan)

	progressTicker := time.NewTicker(10 * time.Second)
	defer progressTicker.Stop()

	var lastTime uint64

	index := start
	for index < upTo {
		max := index + 1024
		if max >= upTo {
			max = upTo - 1
		}

		resp, err := ctLog.GetRawEntries(ctx, int64(index), int64(max))
		if err != nil {
			return index, lastTime, err
		}

		for _, entry := range resp.Entries {
			index++
			logEntry, err := ct.LogEntryFromLeaf(int64(index), &entry)
			if _, ok := err.(x509.NonFatalErrors); !ok && err != nil {
				fmt.Printf("Erroneous certificate: %v\n", err)
				continue
			}

			// Are there waiting signals?
			select {
			case sig := <-sigChan:
				return index, lastTime, fmt.Errorf("Signal caught: %s", sig)
			case ld.EntryChan <- CtLogEntry{logEntry, log.URL}:
				lastTime = logEntry.Leaf.TimestampedEntry.Timestamp

				ld.Backoff.Reset()
			case <-progressTicker.C:
				ld.Display.UpdateProgress(fmt.Sprintf("[%d]", log.LogID), start, index, upTo)
			default:
				// Channel full, retry
				time.Sleep(ld.Backoff.Duration())
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
		logDownloader.Display.StartDisplay(logDownloader.ThreadWaitGroup)
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
					logDownloader.Download(urlString)
					if !*ctconfig.RunForever {
						return
					}
					sleepTime := time.Duration(*ctconfig.PollingDelay) * time.Minute
					glog.Infof("[%s] Completed. Polling again in %s.\n", urlString, sleepTime)

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
