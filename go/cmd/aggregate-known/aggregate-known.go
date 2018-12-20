package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/golang/glog"
	"github.com/jcjones/ct-mapreduce/config"
	"github.com/jcjones/ct-mapreduce/storage"
	"github.com/mozilla/crlite/go/rootprogram"
	"github.com/vbauerster/mpb"
	"github.com/vbauerster/mpb/decor"
)

const (
	permMode    = 0644
	permModeDir = 0755
)

var (
	inccadb  = flag.String("ccadb", "<path>", "input CCADB CSV path")
	outpath  = flag.String("outpath", "<dir>", "output directory for $issuer.known files")
	ctconfig = config.NewCTConfig()
)

type knownWorkUnit struct {
	issuer   string
	expDates []string
}

func knownWorker(wg *sync.WaitGroup, workChan <-chan knownWorkUnit, quitChan <-chan struct{}, storageDB storage.CertDatabase, progBar *mpb.Bar) {
	defer wg.Done()

	lastTime := time.Now()

	for tuple := range workChan {
		aggKnownPath := filepath.Join(*outpath, fmt.Sprintf("%s.known", tuple.issuer))

		aggKnownCerts := storage.NewKnownCertificates(aggKnownPath, permMode)
		// TODO: Track differences
		// if err := aggKnownCerts.Load(); err != nil {
		// 	glog.Infof("Making new known storage file %s", aggKnownPath)
		// }

		for _, expDate := range tuple.expDates {
			select {
			case <-quitChan:
				if err := aggKnownCerts.Save(); err != nil {
					glog.Fatalf("[%s] Could not save known certificates file: %s", aggKnownPath, err)
				}
				return
			default:
				known := storage.GetKnownCertificates(*ctconfig.CertPath, expDate, tuple.issuer, permMode)
				if err := known.Load(); err != nil {
					glog.Errorf("[%s] Could not load known certificates : %s", filepath.Join(*ctconfig.CertPath, expDate, tuple.issuer), err)
				}

				if err := aggKnownCerts.Merge(known); err != nil {
					glog.Errorf("[%s] Could not merge known certificates : %s", filepath.Join(*ctconfig.CertPath, expDate, tuple.issuer), err)
				}

				progBar.IncrBy(1, time.Since(lastTime))
				lastTime = time.Now()
			}
		}

		if err := aggKnownCerts.Save(); err != nil {
			glog.Fatalf("[%s] Could not save known certificates file: %s", aggKnownPath, err)
		}
	}

}

func main() {
	var err error
	var storageDB storage.CertDatabase
	if ctconfig.CertPath != nil && len(*ctconfig.CertPath) > 0 {
		glog.Infof("Opening disk at %s", *ctconfig.CertPath)
		storageDB, err = storage.NewDiskDatabase(*ctconfig.NumThreads, *ctconfig.CertPath, permMode)
		if err != nil {
			glog.Fatalf("unable to open Certificate Path: %s: %s", *ctconfig.CertPath, err)
		}
	}

	if storageDB == nil || *outpath == "<dir>" {
		ctconfig.Usage()
		os.Exit(2)
	}

	if err := os.MkdirAll(*outpath, permModeDir); err != nil {
		glog.Fatalf("Unable to make the output directory: %s", err)
	}

	mozIssuers := rootprogram.NewMozillaIssuers()
	if *inccadb != "<path>" {
		if err := mozIssuers.LoadFromDisk(*inccadb); err != nil {
			glog.Fatalf("Failed to load issuers from disk: %s", err)
		}
	} else {
		if err := mozIssuers.Load(); err != nil {
			glog.Fatalf("Failed to load issuers: %s", err)
		}
	}

	var wg sync.WaitGroup
	workChan := make(chan knownWorkUnit, 16*1024*1024)

	// Handle signals from the OS
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, os.Interrupt)
	defer signal.Stop(sigChan)

	// Exit signal, used by signals from the OS
	quitChan := make(chan struct{})

	expDates, err := storageDB.ListExpirationDates(time.Now())
	if err != nil {
		glog.Fatalf("Could not list expiration dates: %s", err)
	}

	issuerToWorkUnit := make(map[string]knownWorkUnit)

	var count int64
	for _, expDate := range expDates {
		issuers, err := storageDB.ListIssuersForExpirationDate(expDate)
		if err != nil {
			glog.Fatalf("Could not list issuers (%s) %s", expDate, err)
		}

		for _, issuer := range issuers {
			if !mozIssuers.IsIssuerInProgram(issuer) {
				continue
			}

			glog.V(1).Infof("%s/%s", expDate, issuer)
			count = count + 1

			wu, ok := issuerToWorkUnit[issuer]
			if !ok {
				wu = knownWorkUnit{issuer: issuer}
			}
			wu.expDates = append(wu.expDates, expDate)
			issuerToWorkUnit[issuer] = wu
		}
	}

	for _, wu := range issuerToWorkUnit {
		select {
		case workChan <- wu:
		default:
			glog.Fatalf("Channel overflow. Aborting at %+v", wu)
		}
	}

	// Signal that was the last work
	close(workChan)

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
		go knownWorker(&wg, workChan, quitChan, storageDB, progressBar)
	}

	// Set up a notifier for the workers closing
	doneChan := make(chan bool)
	go func(wait *sync.WaitGroup) {
		wg.Wait()
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
