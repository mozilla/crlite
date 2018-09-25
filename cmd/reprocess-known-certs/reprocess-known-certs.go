package main

import (
	"flag"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/golang/glog"
	"github.com/jcjones/ct-mapreduce/config"
	"github.com/jcjones/ct-mapreduce/storage"
)

var (
	ctconfig = config.NewCTConfig()
)

type metadataTuple struct {
	expDate string
	issuer  string
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
	glog.Infof("OK, operating on:")
	for _, path := range flag.Args() {
		glog.Infof("Path: %s", path)
	}

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
			metaChan <- metadataTuple{expDate, issuer}
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
