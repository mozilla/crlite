package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sync"
	"syscall"
	"time"

	"github.com/golang/glog"
	"github.com/jcjones/ct-mapreduce/config"
	"github.com/jcjones/ct-mapreduce/storage"
)

var (
	ctconfig = config.NewCTConfig()

	matchingRegexes = make([]*regexp.Regexp, 0)
)

type metadataTuple struct {
	expDate string
	issuer  string
}

func shouldProcess(expDate, issuer string) bool {
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

func metadataWorker(wg *sync.WaitGroup, metaChan <-chan metadataTuple, quitChan <-chan bool, storageDB storage.CertDatabase) {
	defer wg.Done()

	for tuple := range metaChan {
		select {
		case <-quitChan:
			return
		default:
			glog.V(1).Infof("Processing %s", filepath.Join(*ctconfig.CertPath, tuple.expDate, tuple.issuer))

			if err := storageDB.ReconstructIssuerMetadata(tuple.expDate, tuple.issuer); err != nil {
				glog.Fatalf("Error reconstructing issuer metadata (%s / %s) %s", tuple.expDate, tuple.issuer, err)
			}
		}
	}
}

func main() {
	var err error
	var storageDB storage.CertDatabase
	if ctconfig.CertPath != nil && len(*ctconfig.CertPath) > 0 {
		glog.Infof("Loading from disk at %s", *ctconfig.CertPath)
		storageDB, err = storage.NewDiskDatabase(*ctconfig.CacheSize, *ctconfig.CertPath, 0644)
		if err != nil {
			glog.Fatalf("unable to open Certificate Path: %s: %s", ctconfig.CertPath, err)
		}
	}

	if storageDB == nil {
		ctconfig.Usage()
		fmt.Println()
		fmt.Println("Non-flag arguments are interpreted as regular expressions to be matched.")
		fmt.Println()
		os.Exit(2)
	}

	var wg sync.WaitGroup
	metaChan := make(chan metadataTuple, 1024*1024)

	// Handle signals from the OS
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, os.Interrupt)
	defer signal.Stop(sigChan)

	// Exit signal, used by signals from the OS
	quitChan := make(chan bool)

	// Start the workers
	for t := 0; t < *ctconfig.NumThreads; t++ {
		wg.Add(1)
		go metadataWorker(&wg, metaChan, quitChan, storageDB)
	}

	// Set up a notifier for stopping at the end
	doneChan := make(chan bool)
	go func(wait *sync.WaitGroup) {
		wg.Wait()
		doneChan <- true
	}(&wg)

	expDates, err := storageDB.ListExpirationDates(time.Now())
	if err != nil {
		glog.Fatalf("Could not list expiration dates", err)
	}

	for _, expDate := range expDates {
		issuers, err := storageDB.ListIssuersForExpirationDate(expDate)
		if err != nil {
			glog.Fatalf("Could not list issuers (%s) %s", expDate, err)
		}

		for _, issuer := range issuers {
			if shouldProcess(expDate, issuer) {
				metaChan <- metadataTuple{expDate, issuer}
			}
		}
	}

	// Signal that was the last work
	close(metaChan)

	select {
	case <-sigChan:
		glog.Infof("Signal caught, stopping threads at next opportunity.")
		quitChan <- true
	case <-doneChan:
		glog.Infof("Completed.")
	}
}
