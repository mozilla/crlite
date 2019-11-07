package main

import (
	"context"
	"encoding/pem"
	"flag"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sync"
	"syscall"
	"time"

	"github.com/armon/go-metrics"
	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/jcjones/ct-mapreduce/config"
	"github.com/jcjones/ct-mapreduce/engine"
	"github.com/jcjones/ct-mapreduce/storage"
	"github.com/vbauerster/mpb/v4"
	"github.com/vbauerster/mpb/v4/decor"

	"cloud.google.com/go/profiler"
)

var (
	ctconfig = config.NewCTConfig()

	matchingRegexes = make([]*regexp.Regexp, 0)
)

const kProgressPeriod int64 = 64

type issuerDateTuple struct {
	expDate string
	issuer  storage.Issuer
}

type certSerialTuple struct {
	expDate   string
	issuer    storage.Issuer
	serialNum storage.Serial
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

// This worker obtains all the serials for issuer/expDate combinations provided
// by the input channel, filters them on whether the cache knows the serial yet,
// and puts the unknown serials onto the output channel.
func issuerAndDateWorker(wg *sync.WaitGroup, metaChan <-chan issuerDateTuple,
	certSerialChan chan<- certSerialTuple, quitChan <-chan struct{},
	issuerDateProgressBar *mpb.Bar, serialProgressBar *mpb.Bar,
	storageDB storage.CertDatabase, backendDB storage.StorageBackend) {
	defer wg.Done()
	topCtx := context.Background()

	for tuple := range metaChan {
		select {
		case <-quitChan:
			return
		default:
			glog.V(1).Infof("Processing %s / %s", tuple.expDate, tuple.issuer.ID())

			startTime := time.Now()

			knownCerts := storageDB.GetKnownCertificates(tuple.expDate, tuple.issuer)

			ctx, ctxCancel := context.WithCancel(topCtx)
			serialChan, err := backendDB.StreamSerialsForExpirationDateAndIssuer(ctx, tuple.expDate, tuple.issuer)
			if err != nil {
				glog.Fatalf("ReconstructIssuerMetadata StreamSerialsForExpirationDateAndIssuer %v", err)
			}
			metrics.MeasureSince([]string{"ReconstructIssuerMetadata", "ListSerials"}, startTime)

			var progCount int
			for serialNum := range serialChan {
				certWasUnknown, err := knownCerts.WasUnknown(serialNum)
				if err != nil {
					glog.Fatalf("ReconstructIssuerMetadata WasUnknown %v", err)
				}

				if !certWasUnknown {
					metrics.IncrCounter([]string{"ReconstructIssuerMetadata", "certWasKnown"}, 1)
					continue
				}

				metrics.IncrCounter([]string{"ReconstructIssuerMetadata", "certWasUnknown"}, 1)
				certSerialChan <- certSerialTuple{
					serialNum: serialNum,
					expDate:   tuple.expDate,
					issuer:    tuple.issuer,
				}

				progCount += 1
				if int64(progCount) == kProgressPeriod {
					currentVal := serialProgressBar.Current()
					serialProgressBar.SetTotal(currentVal+1024*1024, false)
					progCount = 0
				}
			}

			ctxCancel()
			metrics.MeasureSince([]string{"ReconstructIssuerMetadata"}, startTime)
			issuerDateProgressBar.IncrBy(1, time.Since(startTime))
		}
	}
}

// This worker does the heavy lifting of loading a PEM, parsing it, and pulling out
// the issuerDN and CRLs for the metadata cache. It should only be provided serials
// which aren't already known.
func certProcessingWorker(wg *sync.WaitGroup, certSerialChan <-chan certSerialTuple,
	quitChan <-chan struct{}, serialProgressBar *mpb.Bar, storageDB storage.CertDatabase,
	backendDB storage.StorageBackend) {
	defer wg.Done()
	ctx := context.Background()

	for tuple := range certSerialChan {
		select {
		case <-quitChan:
			return
		default:
			glog.V(2).Infof("Processing serial=%s expDate=%s issuer=%s", tuple.serialNum,
				tuple.expDate, tuple.issuer.ID())
		}

		subCtx, subCancel := context.WithTimeout(ctx, 1*time.Minute)

		pemTime := time.Now()
		pemBytes, err := backendDB.LoadCertificatePEM(subCtx, tuple.serialNum, tuple.expDate,
			tuple.issuer)
		subCancel()
		if err != nil {
			glog.Fatalf("ReconstructIssuerMetadata error LoadCertificatePEM %v", err)
		}
		metrics.MeasureSince([]string{"ReconstructIssuerMetadata", "Load"}, pemTime)

		decodeTime := time.Now()
		block, rest := pem.Decode(pemBytes)
		if len(rest) > 0 {
			glog.Fatalf("PEM data for %s %s %s had extra bytes: %+v", tuple.serialNum, tuple.expDate,
				tuple.issuer.ID(), rest)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			metrics.IncrCounter([]string{"ReconstructIssuerMetadata", "certParseError"}, 1)
			glog.Fatalf("ReconstructIssuerMetadata error ParseCertificate %v", err)
		}
		metrics.MeasureSince([]string{"ReconstructIssuerMetadata", "DecodeParse"}, decodeTime)

		redisTime := time.Now()
		_, err = storageDB.GetIssuerMetadata(tuple.issuer).Accumulate(cert)
		if err != nil {
			glog.Fatalf("ReconstructIssuerMetadata error Accumulate %v", err)
		}

		metrics.MeasureSince([]string{"ReconstructIssuerMetadata", "CacheInsertion"}, redisTime)

		serialProgressBar.IncrBy(1)
	}
}

func main() {
	ctconfig.Init()

	// Long context is required for these operations
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	val, ok := os.LookupEnv("profile")
	if ok && val == "reprocess-known-certs" {
		glog.Info("Profiling to Stackdriver")
		if err := profiler.Start(profiler.Config{
			Service:        "reprocess-known-certs",
			ServiceVersion: "20191106",
			MutexProfiling: true,
		}); err != nil {
			glog.Errorf("Could not start profiler: %s", err)
		}
	}

	storageDB, _, backend := engine.GetConfiguredStorage(ctx, ctconfig)

	engine.PrepareTelemetry("reprocess-known-certs", ctconfig)
	defer glog.Flush()

	issuerDateChan := make(chan issuerDateTuple, 16*1024*1024)

	// Handle signals from the OS
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, os.Interrupt)
	defer signal.Stop(sigChan)

	// Start the display
	refreshDur, err := time.ParseDuration(*ctconfig.OutputRefreshPeriod)
	if err != nil {
		glog.Fatal(err)
	}

	glog.Infof("Progress bar refresh rate is every %s.\n", refreshDur.String())

	var topWg sync.WaitGroup

	display := mpb.NewWithContext(ctx,
		mpb.WithWaitGroup(&topWg),
		mpb.WithRefreshRate(refreshDur),
	)

	listExpDateTime := time.Now()
	expDates, err := storageDB.ListExpirationDates(time.Now())
	if err != nil {
		glog.Fatalf("Could not list expiration dates: %+v", err)
	}
	metrics.MeasureSince([]string{"ListExpirationDates"}, listExpDateTime)

	fetchingJobs := display.AddBar(int64(len(expDates)),
		mpb.BarRemoveOnComplete(),
		mpb.AppendDecorators(
			decor.Percentage(),
			decor.Name(" Filling Queue"),
			decor.AverageETA(decor.ET_STYLE_GO, decor.WC{W: 14}),
			decor.CountersNoUnit("%d / %d", decor.WCSyncSpace),
		),
	)

	var count int64
	for _, expDate := range expDates {
		listIssuersTime := time.Now()
		issuers, err := storageDB.ListIssuersForExpirationDate(expDate)
		if err != nil {
			glog.Fatalf("Could not list issuers (%s) %+v", expDate, err)
		}
		metrics.MeasureSince([]string{"ListIssuersForExpirationDate"}, listIssuersTime)

		lastTime := time.Now()
		for _, issuer := range issuers {
			fetchingJobs.IncrBy(1, time.Since(lastTime))
			lastTime = time.Now()

			if shouldProcess(expDate, issuer.ID()) {
				select {
				case issuerDateChan <- issuerDateTuple{expDate, issuer}:
					count = count + 1
				default:
					glog.Fatalf("Channel overflow. Aborting at %s %s", expDate, issuer.ID())
				}
			}
		}
	}

	// Signal that was the last work
	close(issuerDateChan)

	expIssuerProgressBar := display.AddBar(count,
		mpb.AppendDecorators(
			decor.Percentage(decor.WC{W: 6, C: decor.DidentRight}),
			decor.Name("ExpDate/Issuers"),
			decor.AverageETA(decor.ET_STYLE_GO, decor.WC{W: 14}),
			decor.CountersNoUnit("%d / %d", decor.WCSyncSpace),
		),
	)

	serialProgressBar := display.AddBar(1*1024*1024,
		mpb.AppendDecorators(
			decor.Name("Unknown Certs Processed"),
			decor.CountersNoUnit("%d%.T", decor.WC{W: 8}), // %.T ignores the total
			decor.AverageSpeed(0, "%.1f/s", decor.WC{W: 8}),
			decor.Elapsed(decor.ET_STYLE_GO, decor.WCSyncSpace),
		),
	)

	// Exit signal, used by signals from the OS
	quitChan := make(chan struct{})

	certSerialChan := make(chan certSerialTuple, 1*1024*1024)

	var issuerDateWorkerWg sync.WaitGroup
	// Start the issuer/date workers, they populate certSerialChan
	for t := 0; t < *ctconfig.NumThreads; t++ {
		issuerDateWorkerWg.Add(1)
		go issuerAndDateWorker(&issuerDateWorkerWg, issuerDateChan, certSerialChan,
			quitChan, expIssuerProgressBar, serialProgressBar, storageDB, backend)
	}

	// When all the issuerDateWorkers are complete, close the outChan
	go func(wait *sync.WaitGroup) {
		wait.Wait()
		close(certSerialChan)
	}(&issuerDateWorkerWg)

	for t := 0; t < *ctconfig.NumThreads; t++ {
		topWg.Add(1)
		go certProcessingWorker(&topWg, certSerialChan, quitChan, serialProgressBar, storageDB, backend)
	}

	// Set up a notifier for the processing workers' completion to signal our final stop
	doneChan := make(chan bool)
	go func(wait *sync.WaitGroup) {
		wait.Wait()
		doneChan <- true
	}(&topWg)

	select {
	case <-sigChan:
		glog.Infof("Signal caught, stopping threads at next opportunity.")
		cancel()
		close(quitChan)
	case <-doneChan:
		serialProgressBar.SetTotal(serialProgressBar.Current(), true)
		cancel()
		glog.Infof("Completed.")
	}
}
