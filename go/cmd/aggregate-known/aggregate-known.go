package main

import (
	"flag"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/golang/glog"
	"github.com/jcjones/ct-mapreduce/config"
	"github.com/jcjones/ct-mapreduce/engine"
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
	issuer   storage.Issuer
	expDates []string
}

type knownWorker struct {
	loadStorage storage.StorageBackend
	saveStorage storage.StorageBackend
	progBar     *mpb.Bar
}

func (kw knownWorker) run(wg *sync.WaitGroup, workChan <-chan knownWorkUnit, quitChan <-chan struct{}) {
	defer wg.Done()

	lastTime := time.Now()

	for tuple := range workChan {
		aggKnownCerts := storage.NewKnownCertificates("known", tuple.issuer, kw.saveStorage)
		// TODO: Track differences

		for _, expDate := range tuple.expDates {
			select {
			case <-quitChan:
				if err := aggKnownCerts.Save(); err != nil {
					glog.Fatalf("[%s] Could not save known certificates file: %s", tuple.issuer.ID(), err)
				}
				return
			default:
				known := storage.NewKnownCertificates(expDate, tuple.issuer, kw.loadStorage)
				if err := known.Load(); err != nil {
					glog.Errorf("[%s] Could not load known certificates : %s", tuple.issuer.ID(), err)
				}

				if err := aggKnownCerts.Merge(known); err != nil {
					glog.Errorf("[%s] Could not merge known certificates : %s", tuple.issuer.ID(), err)
				}

				kw.progBar.IncrBy(1, time.Since(lastTime))
				lastTime = time.Now()
			}
		}

		if err := aggKnownCerts.Save(); err != nil {
			glog.Fatalf("[%s] Could not save known certificates file: %s", tuple.issuer.ID(), err)
		}
	}

}

func main() {
	storageDB, loadBackend := engine.GetConfiguredStorage(ctconfig)

	if *outpath == "<dir>" {
		glog.Fatalf("You must set an output directory")
	}

	if err := os.MkdirAll(*outpath, permModeDir); err != nil {
		glog.Fatalf("Unable to make the output directory: %s", err)
	}

	saveBackend := storage.NewLocalDiskBackend(permMode, *outpath)

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

			glog.V(1).Infof("%s/%s", expDate, issuer.ID())
			count = count + 1

			wu, ok := issuerToWorkUnit[issuer.ID()]
			if !ok {
				wu = knownWorkUnit{issuer: issuer}
			}
			wu.expDates = append(wu.expDates, expDate)
			issuerToWorkUnit[issuer.ID()] = wu
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
		worker := knownWorker{
			loadStorage: loadBackend,
			saveStorage: saveBackend,
			progBar:     progressBar,
		}
		go worker.run(&wg, workChan, quitChan)
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
