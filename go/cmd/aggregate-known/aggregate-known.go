package main

import (
	"context"
	"flag"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/golang/glog"
	"github.com/mozilla/crlite/go/config"
	"github.com/mozilla/crlite/go/engine"
	"github.com/mozilla/crlite/go/rootprogram"
	"github.com/mozilla/crlite/go/storage"
	"github.com/vbauerster/mpb/v5"
	"github.com/vbauerster/mpb/v5/decor"
)

const (
	permMode    = 0644
	permModeDir = 0755
)

var (
	enrolledpath = flag.String("enrolledpath", "<path>", "input enrolled issuers JSON")
	knownpath    = flag.String("knownpath", "<dir>", "output directory for <issuer> files")
	nobars       = flag.Bool("nobars", false, "disable display of download bars")
	ctconfig     = config.NewCTConfig()
)

type knownWorkUnit struct {
	issuer   storage.Issuer
	issuerDN string
	expDates []storage.ExpDate
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
		var serialCount int
		serials := make([]storage.Serial, 0, 128*1024)

		for _, expDate := range tuple.expDates {
			select {
			case <-quitChan:
				glog.Warningf("Signal on worker quit channel, quitting (count=%d).", serialCount)
				return
			default:
				if expDate.IsExpiredAt(time.Now()) {
					if glog.V(1) {
						glog.Warningf("Date %s is expired now, skipping (issuer=%s)", expDate, tuple.issuer.ID())
					}
					continue
				}

				known := storage.NewKnownCertificates(expDate, tuple.issuer, kw.remoteCache)

				knownSet := known.Known()
				knownSetLen := len(knownSet)

				if knownSetLen == 0 {
					// This is almost certainly due to an hour-rollover since the loader ran, and expired all the next hour's
					// certs.
					glog.Warningf("No cached certificates for issuer=%s (%s) expDate=%s, but the loader thought there should be."+
						" (current count this worker=%d)", tuple.issuerDN, tuple.issuer.ID(), expDate, serialCount)
				}

				serials = append(serials, knownSet...)
				serialCount += knownSetLen

				// This assertion should catch issues where append failed to append everything. For improvement
				// in processing speed, pull this out, but right now it seems valuable.
				if len(serials) != serialCount {
					glog.Fatalf("expDate=%s issuer=%s serial count math error! expected %d but got %d", expDate,
						tuple.issuer.ID(), serialCount, len(serials))
				}

				kw.progBar.Increment()
			}
		}

		if err := kw.saveStorage.StoreKnownCertificateList(ctx, tuple.issuer, serials); err != nil {
			glog.Fatalf("[%s] Could not save known certificates file: %s", tuple.issuer.ID(), err)
		}

		glog.Infof("[%s] %d total known serials for %s (times=%d, len=%d, cap=%d)", tuple.issuer.ID(),
			serialCount, tuple.issuerDN, len(tuple.expDates), len(serials), cap(serials))
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
	storageDB, remoteCache := engine.GetConfiguredStorage(ctx, ctconfig)
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

	glog.Infof("Listing issuers and their expiration dates...")
	issuerList, err := storageDB.GetIssuerAndDatesFromCache()
	if err != nil {
		glog.Fatal(err)
	}

	var count int64
	for _, iObj := range issuerList {
		if mozIssuers.IsIssuerEnrolled(iObj.Issuer) {
			count = count + int64(len(iObj.ExpDates))
		} else {
			if mozIssuers.IsIssuerInProgram(iObj.Issuer) {
				subj, err := mozIssuers.GetSubjectForIssuer(iObj.Issuer)
				if err != nil {
					glog.Error(err)
				}
				glog.Infof("Skipping in-program issuer ID=%s that is not enrolled: %s",
					iObj.Issuer.ID(), subj)
			}
		}
	}

	workChan := make(chan knownWorkUnit, count)
	for _, iObj := range issuerList {
		if !mozIssuers.IsIssuerEnrolled(iObj.Issuer) {
			continue
		}

		issuerSubj, err := mozIssuers.GetSubjectForIssuer(iObj.Issuer)
		if err != nil {
			glog.Warningf("Couldn't get subject for issuer=%s that is in the root program: %s",
				iObj.Issuer.ID(), err)
			issuerSubj = "<unknown>"
		}

		wu := knownWorkUnit{
			issuer:   iObj.Issuer,
			issuerDN: issuerSubj,
			expDates: iObj.ExpDates,
		}

		select {
		case workChan <- wu:
		default:
			glog.Fatalf("Channel overflow. Aborting at %+v", wu)
		}
	}

	// Signal that was the last work
	close(workChan)

	var barOutput io.Writer = nil
	if nobars != nil && !*nobars {
		barOutput = os.Stdout
	}

	// Start the display
	display := mpb.NewWithContext(ctx,
		mpb.WithRefreshRate(refreshDur),
		mpb.WithOutput(barOutput),
	)

	progressBar := display.AddBar(count,
		mpb.AppendDecorators(
			decor.Percentage(),
			decor.Name(""),
			decor.AverageETA(decor.ET_STYLE_GO, decor.WC{W: 14}),
			decor.CountersNoUnit("%d / %d", decor.WCSyncSpace),
		),
		mpb.BarRemoveOnComplete(),
	)

	glog.Infof("Starting worker processes to handle %d work units", count)

	// Handle signals from the OS
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, os.Interrupt)
	defer signal.Stop(sigChan)

	// Exit signal, used by signals from the OS
	quitChan := make(chan struct{})

	var wg sync.WaitGroup

	// Start the workers
	for t := 0; t < *ctconfig.NumThreads; t++ {
		wg.Add(1)
		worker := knownWorker{
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
