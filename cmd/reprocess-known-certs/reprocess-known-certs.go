package main

import (
	"flag"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sync"
	"syscall"
	"time"

	"github.com/golang/glog"
	"github.com/jcjones/ct-mapreduce/config"
	"github.com/jcjones/ct-mapreduce/engine"
	"github.com/jcjones/ct-mapreduce/storage"
	"github.com/vbauerster/mpb"
	"github.com/vbauerster/mpb/decor"
)

var (
	ctconfig = config.NewCTConfig()

	matchingRegexes = make([]*regexp.Regexp, 0)
)

type metadataTuple struct {
	expDate string
	issuer  storage.Issuer
}

func shouldProcess(expDate string, issuer string) bool {
	if len(flag.Args()) == 0 {
		return true
	}

	// Lazily initialize
	if len(matchingRegexes) == 0 {
		for _, matchStr := range flag.Args() {
			rx, err := regexp.Compile(matchStr)

			if err != nil {
				glog.Fatalf("Could not compile regex [%s] %s", matchStr, err)
				os.Exit(1)
			}

			matchingRegexes = append(matchingRegexes, rx)
		}
	}

	// Try and match on one of the provided arguments
	for _, matcher := range matchingRegexes {
		if matcher.MatchString(expDate) || matcher.MatchString(issuer) ||
			matcher.MatchString(filepath.Join(expDate, issuer)) {
			return true
		}
	}
	return false
}

func metadataWorker(wg *sync.WaitGroup, metaChan <-chan metadataTuple, quitChan <-chan struct{}, progBar *mpb.Bar, storageDB storage.CertDatabase) {
	defer wg.Done()

	lastTime := time.Now()

	for tuple := range metaChan {
		select {
		case <-quitChan:
			return
		default:
			path := filepath.Join(*ctconfig.CertPath, tuple.expDate, tuple.issuer.ID())
			glog.V(1).Infof("Processing %s", path)

			if err := storageDB.ReconstructIssuerMetadata(tuple.expDate, tuple.issuer); err != nil {
				glog.Errorf("%s: Error reconstructing issuer metadata, file not totally read. Err=%s", path, err)
			}

			progBar.IncrBy(1, time.Since(lastTime))
			lastTime = time.Now()
		}
	}
}

func main() {
	storageDB, _, _ := engine.GetConfiguredStorage(ctconfig)

	var wg sync.WaitGroup
	workUnitsChan := make(chan metadataTuple, 16*1024*1024)

	// Handle signals from the OS
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, os.Interrupt)
	defer signal.Stop(sigChan)

	// Exit signal, used by signals from the OS
	quitChan := make(chan struct{})

	expDates, err := storageDB.ListExpirationDates(time.Now())
	if err != nil {
		glog.Fatalf("Could not list expiration dates: %+v", err)
	}

	var count int64
	for _, expDate := range expDates {
		issuers, err := storageDB.ListIssuersForExpirationDate(expDate)
		if err != nil {
			glog.Fatalf("Could not list issuers (%s) %+v", expDate, err)
		}

		for _, issuer := range issuers {
			if shouldProcess(expDate, issuer.ID()) {
				select {
				case workUnitsChan <- metadataTuple{expDate, issuer}:
					count = count + 1
				default:
					glog.Fatalf("Channel overflow. Aborting at %s %s", expDate, issuer.ID())
				}
			}
		}
	}

	// Signal that was the last work
	close(workUnitsChan)

	// Start the display
	display := mpb.New()

	progressBar := display.AddBar(count,
		mpb.AppendDecorators(
			decor.Percentage(),
			decor.Name(""),
			decor.EwmaETA(decor.ET_STYLE_GO, 128, decor.WC{W: 14}),
			decor.CountersNoUnit("%d / %d", decor.WCSyncSpace),
		),
	)

	// Start the workers
	for t := 0; t < *ctconfig.NumThreads; t++ {
		wg.Add(1)
		go metadataWorker(&wg, workUnitsChan, quitChan, progressBar, storageDB)
	}

	// Set up a notifier for the workers closing
	doneChan := make(chan bool)
	go func(wait *sync.WaitGroup) {
		wait.Wait()
		doneChan <- true
	}(&wg)

	select {
	case <-sigChan:
		glog.Infof("Signal caught, stopping threads at next opportunity.")
		quitChan <- struct{}{}
	case <-doneChan:
		glog.Infof("Completed.")
	}
}
