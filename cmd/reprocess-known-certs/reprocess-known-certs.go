package main

import (
	"context"
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

	ctx, cancel := context.WithCancel(context.Background())
	var twg sync.WaitGroup
	workUnitsChan := make(chan metadataTuple, 16*1024*1024)

	// Handle signals from the OS
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, os.Interrupt)
	defer signal.Stop(sigChan)

	// Exit signal, used by signals from the OS
	quitChan := make(chan struct{})

	// Start the display
	refreshDur := time.Duration(int64(*ctconfig.OutputRefreshMs)) * time.Millisecond

	glog.Infof("Progress bar refresh rate %d is every %s.\n", *ctconfig.OutputRefreshMs, refreshDur.String())

	display := mpb.New(
		mpb.WithWaitGroup(&twg),
		mpb.WithContext(ctx),
		mpb.WithRefreshRate(refreshDur),
	)

	expDates, err := storageDB.ListExpirationDates(time.Now())
	if err != nil {
		glog.Fatalf("Could not list expiration dates: %+v", err)
	}

	fetchingJobs := display.AddBar(int64(len(expDates)),
		mpb.AppendDecorators(
			decor.Percentage(),
			decor.Name(" Filling Queue"),
			decor.EwmaETA(decor.ET_STYLE_GO, 128, decor.WC{W: 14}),
			decor.CountersNoUnit("%d / %d", decor.WCSyncSpace),
		),
	)

	var count int64
	for _, expDate := range expDates {
		issuers, err := storageDB.ListIssuersForExpirationDate(expDate)
		if err != nil {
			glog.Fatalf("Could not list issuers (%s) %+v", expDate, err)
		}

		lastTime := time.Now()
		for _, issuer := range issuers {
			fetchingJobs.IncrBy(1, time.Since(lastTime))
			lastTime = time.Now()

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

	progressBar := display.AddBar(count,
		mpb.AppendDecorators(
			decor.Percentage(),
			decor.Name(" ExpDate/Issuers"),
			decor.EwmaETA(decor.ET_STYLE_GO, 128, decor.WC{W: 14}),
			decor.CountersNoUnit("%d / %d", decor.WCSyncSpace),
		),
	)

	// Start the workers
	for t := 0; t < *ctconfig.NumThreads; t++ {
		twg.Add(1)
		go metadataWorker(&twg, workUnitsChan, quitChan, progressBar, storageDB)
	}

	// Set up a notifier for the workers closing
	doneChan := make(chan bool)
	go func(wait *sync.WaitGroup) {
		wait.Wait()
		doneChan <- true
	}(&twg)

	select {
	case <-sigChan:
		glog.Infof("Signal caught, stopping threads at next opportunity.")
		cancel()
		quitChan <- struct{}{}
	case <-doneChan:
		cancel()
		glog.Infof("Completed.")
	}
}
