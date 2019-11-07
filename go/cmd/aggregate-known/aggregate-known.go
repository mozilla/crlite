package main

import (
	"context"
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
	"github.com/vbauerster/mpb/v4"
	"github.com/vbauerster/mpb/v4/decor"
)

const (
	permMode    = 0644
	permModeDir = 0755
)

var (
	enrolledpath = flag.String("enrolledpath", "<path>", "input enrolled issuers JSON")
	knownpath    = flag.String("knownpath", "<dir>", "output directory for <issuer> files")
	ctconfig     = config.NewCTConfig()
)

type knownWorkUnit struct {
	issuer   storage.Issuer
	issuerDN string
	expDates []string
}

type knownWorker struct {
	loadStorage storage.StorageBackend
	saveStorage storage.StorageBackend
	remoteCache storage.RemoteCache
	progBar     *mpb.Bar
}

func (kw knownWorker) run(wg *sync.WaitGroup, workChan <-chan knownWorkUnit, quitChan <-chan struct{}) {
	defer wg.Done()

	ctx := context.Background()

	for tuple := range workChan {
		serialCount := 0
		serials := make([]storage.Serial, 0, 128*1024)

		for _, expDate := range tuple.expDates {
			cycleTime := time.Now()

			select {
			case <-quitChan:
				return
			default:
				known := storage.NewKnownCertificates(expDate, tuple.issuer, kw.remoteCache)

				knownSet := known.Known()
				knownSetLen := len(knownSet)

				if knownSetLen == 0 {
					glog.Warningf("No cached certificates for issuer=%s (%s) expDate=%s, but the loader thought there should be."+
						" (current count this worker=%d)", tuple.issuerDN, tuple.issuer.ID(), expDate, serialCount)
				}

				if cap(serials) < knownSetLen+serialCount {
					newSerials := make([]storage.Serial, 0, serialCount+knownSetLen)
					copy(newSerials, serials)
					serials = newSerials
				}

				serials = append(serials, knownSet...)
				serialCount += knownSetLen

				kw.progBar.IncrBy(1, time.Since(cycleTime))
			}
		}

		if err := kw.saveStorage.StoreKnownCertificateList(ctx, tuple.issuer, serials); err != nil {
			glog.Fatalf("[%s] Could not save known certificates file: %s", tuple.issuer.ID(), err)
		}
	}
}

func checkPathArg(strObj string, confOptionName string, ctconfig *config.CTConfig) {
	if strObj == "<path>" {
		glog.Errorf("Flag %s is not set", confOptionName)
		ctconfig.Usage()
		os.Exit(2)
	}
}

func main() {
	ctconfig.Init()
	ctx := context.Background()
	storageDB, remoteCache, loadBackend := engine.GetConfiguredStorage(ctx, ctconfig)
	defer glog.Flush()

	checkPathArg(*enrolledpath, "enrolledpath", ctconfig)
	checkPathArg(*knownpath, "knownpath", ctconfig)

	if err := os.MkdirAll(*knownpath, permModeDir); err != nil {
		glog.Fatalf("Unable to make the output directory: %s", err)
	}

	refreshDur, err := time.ParseDuration(*ctconfig.OutputRefreshPeriod)
	if err != nil {
		glog.Fatal(err)
	}
	glog.Infof("Progress bar refresh rate is every %s.\n", refreshDur.String())

	engine.PrepareTelemetry("aggregate-known", ctconfig)

	saveBackend := storage.NewLocalDiskBackend(permMode, *knownpath)

	mozIssuers := rootprogram.NewMozillaIssuers()
	if err := mozIssuers.LoadEnrolledIssuers(*enrolledpath); err != nil {
		glog.Fatalf("Failed to load enrolled issuers from disk: %s", err)
	}

	glog.Infof("%d issuers loaded", len(mozIssuers.GetIssuers()))

	var wg sync.WaitGroup
	workChan := make(chan knownWorkUnit, 16*1024*1024)

	// Handle signals from the OS
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, os.Interrupt)
	defer signal.Stop(sigChan)

	// Exit signal, used by signals from the OS
	quitChan := make(chan struct{})

	glog.Infof("Listing expiration dates...")
	expDates, err := storageDB.ListExpirationDates(time.Now())
	if err != nil {
		glog.Fatalf("Could not list expiration dates: %s", err)
	}
	glog.Infof("Processing %d expiration dates...", len(expDates))

	issuerToWorkUnit := make(map[string]knownWorkUnit)

	var count int64
	for _, expDate := range expDates {
		issuers, err := storageDB.ListIssuersForExpirationDate(expDate)
		if err != nil {
			glog.Fatalf("Could not list issuers (%s) %s", expDate, err)
		}

		glog.V(1).Infof("Issuers for %s (%d)", expDate, len(issuers))

		for _, issuer := range issuers {
			if !mozIssuers.IsIssuerEnrolled(issuer) {
				continue
			}

			glog.V(1).Infof("(%d) Collating %s/%s", count, expDate, issuer.ID())
			count = count + 1

			wu, ok := issuerToWorkUnit[issuer.ID()]
			if !ok {
				issuerSubj, err := mozIssuers.GetSubjectForIssuer(issuer)
				if err != nil {
					glog.Warningf("Couldn't get subject for issuer=%s that is in the root program: %s",
						issuer.ID(), err)
					issuerSubj = "<unknown>"
				}
				wu = knownWorkUnit{
					issuer:   issuer,
					issuerDN: issuerSubj,
				}
			}
			wu.expDates = append(wu.expDates, expDate)
			issuerToWorkUnit[issuer.ID()] = wu
		}
	}

	glog.V(1).Infof("Filling work channel...")
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
	display := mpb.NewWithContext(ctx,
		mpb.WithRefreshRate(refreshDur),
	)

	progressBar := display.AddBar(count,
		mpb.AppendDecorators(
			decor.Percentage(),
			decor.Name(""),
			decor.EwmaETA(decor.ET_STYLE_GO, 128, decor.WC{W: 14}),
			decor.CountersNoUnit("%d / %d", decor.WCSyncSpace),
		),
		mpb.BarRemoveOnComplete(),
	)

	glog.Infof("Starting worker processes to handle %d work units", count)

	// Start the workers
	for t := 0; t < *ctconfig.NumThreads; t++ {
		wg.Add(1)
		worker := knownWorker{
			loadStorage: loadBackend,
			saveStorage: saveBackend,
			progBar:     progressBar,
			remoteCache: remoteCache,
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
