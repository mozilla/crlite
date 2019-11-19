package main

import (
	"context"
	"encoding/pem"
	"flag"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"cloud.google.com/go/profiler"
	"github.com/armon/go-metrics"
	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/jcjones/ct-mapreduce/config"
	"github.com/jcjones/ct-mapreduce/engine"
	"github.com/jcjones/ct-mapreduce/storage"
	"github.com/jpillora/backoff"
	"github.com/vbauerster/mpb/v4"
	"github.com/vbauerster/mpb/v4/decor"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	ctconfig = config.NewCTConfig()

	matchingRegexes = make([]*regexp.Regexp, 0)
)

const kIssuerExpdateQueueName string = "reprocess-issuerExpDateWorkQueue"

type issuerDateTuple struct {
	expDate storage.ExpDate
	issuer  storage.Issuer
}

func decodeIssuerDateTuple(s string) issuerDateTuple {
	e, issuerStr := filepath.Split(s)
	expDate, err := storage.NewExpDate(e[:len(e)-1]) // trailing slash
	if err != nil {
		glog.Fatalf("Could not decode expiration date=%s: %v", e, err)
	}
	return issuerDateTuple{
		expDate: expDate,
		issuer:  storage.NewIssuerFromString(issuerStr),
	}
}

func (t *issuerDateTuple) String() string {
	return filepath.Join(t.expDate.ID(), t.issuer.ID())
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

			glog.Infof("Regex set: %s", matchStr)

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
func issuerAndDateWorker(ctx context.Context, wg *sync.WaitGroup, serialChan chan<- storage.UniqueCertIdentifier,
	quitChan <-chan struct{}, issuerDateProgressBar *mpb.Bar, backendDB storage.StorageBackend,
	extCache storage.RemoteCache) {
	defer wg.Done()

	var tupleStr string
	var err error

	for {
		select {
		case <-quitChan:
			glog.Errorf("Requeuing our place: [%s]", tupleStr)
			if tupleStr != "" {
				// Remember our place
				_, err := extCache.Queue(kIssuerExpdateQueueName, tupleStr)
				if err != nil {
					glog.Errorf("Couldn't re-queue our current place, [%s]: %s", tupleStr, err)
				}
			}
			return
		default:
		}

		tupleStr, err = extCache.Pop(kIssuerExpdateQueueName)
		if err != nil {
			if err.Error() == storage.EMPTY_QUEUE {
				return
			}
			glog.Fatalf("Error popping off cache queue %s: %s", kIssuerExpdateQueueName, err)
		}

		tuple := decodeIssuerDateTuple(tupleStr)

		glog.V(1).Infof("Processing %s / %s", tuple.expDate, tuple.issuer.ID())

		startTime := time.Now()

		subCtx, ctxCancel := context.WithCancel(ctx)
		err = backendDB.StreamSerialsForExpirationDateAndIssuer(subCtx, tuple.expDate, tuple.issuer,
			quitChan, serialChan)
		if err != nil {
			glog.Fatalf("ReconstructIssuerMetadata StreamSerialsForExpirationDateAndIssuer %v", err)
		}

		ctxCancel()
		metrics.MeasureSince([]string{"ReconstructIssuerMetadata"}, startTime)
		issuerDateProgressBar.IncrBy(1, time.Since(startTime))
	}
}

// This worker does the heavy lifting of loading a PEM, parsing it, and pulling out
// the issuerDN and CRLs for the metadata cache. It should only be provided serials
// which aren't already known.
func deduplicationWorker(wg *sync.WaitGroup, certSerialChan <-chan storage.UniqueCertIdentifier,
	unknownSerialChan chan<- storage.UniqueCertIdentifier, storageDB storage.CertDatabase) {
	defer wg.Done()

	for tuple := range certSerialChan {
		knownCerts := storageDB.GetKnownCertificates(tuple.ExpDate, tuple.Issuer)

		certWasUnknown, err := knownCerts.WasUnknown(tuple.SerialNum)
		if err != nil {
			glog.Errorf("WasUnknown failed issuer=%s expDate=%s, serial=%s %v",
				tuple.Issuer.ID(), tuple.ExpDate, tuple.SerialNum, err)
			continue
		}

		if !certWasUnknown {
			metrics.IncrCounter([]string{"ReconstructIssuerMetadata", "certWasKnown"}, 1)
			continue
		}

		metrics.IncrCounter([]string{"ReconstructIssuerMetadata", "certWasUnknown"}, 1)
		unknownSerialChan <- tuple
	}
}

// This worker does the heavy lifting of loading a PEM, parsing it, and pulling out
// the issuerDN and CRLs for the metadata cache. It should only be provided serials
// which aren't already known.
func certProcessingWorker(ctx context.Context, wg *sync.WaitGroup,
	certSerialChan <-chan storage.UniqueCertIdentifier, serialProgressBar *mpb.Bar,
	storageDB storage.CertDatabase, backendDB storage.StorageBackend) {
	defer wg.Done()

	b := &backoff.Backoff{
		Jitter: true,
		Min:    125 * time.Millisecond,
		Max:    30 * time.Second,
	}

	for tuple := range certSerialChan {
		var pemBytes []byte
		var err error

		pemTime := time.Now()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			subCtx, subCancel := context.WithTimeout(ctx, 5*time.Minute)
			pemBytes, err = backendDB.LoadCertificatePEM(subCtx, tuple.SerialNum, tuple.ExpDate,
				tuple.Issuer)
			subCancel()

			if ctx.Err() != nil {
				glog.Fatalf("LoadCertificatePEM fatal top-level context "+
					"failure, issuer=%s expDate=%s, serial=%s. (ctx.Err=%v)", tuple.Issuer.ID(),
					tuple.ExpDate, tuple.SerialNum, ctx.Err())
			} else if err != nil && (status.Code(err) == codes.Unavailable ||
				status.Code(err) == codes.DeadlineExceeded ||
				strings.Contains(err.Error(), "context deadline exceeded")) {
				d := b.Duration()
				if d == b.Max {
					glog.Warningf("LoadCertificatePEM timed out, issuer=%s expDate=%s, serial=%s time=%s"+
						" Retrying in %s: %v", tuple.Issuer.ID(), tuple.ExpDate, tuple.SerialNum,
						time.Since(pemTime), d, err)
				}
				time.Sleep(d)
				continue
			}
			break
		}
		metrics.MeasureSince([]string{"ReconstructIssuerMetadata", "Load"}, pemTime)

		decodeTime := time.Now()
		block, rest := pem.Decode(pemBytes)
		if len(rest) > 0 {
			glog.Errorf("PEM data had extra bytes: issuer=%s expDate=%s, serial=%s %v",
				tuple.Issuer.ID(), tuple.ExpDate, tuple.SerialNum, rest)
		}
		if block == nil {
			metrics.IncrCounter([]string{"ReconstructIssuerMetadata", "certParseError"}, 1)
			glog.Errorf("ParseCertificate had an empty PEM, len=%d issuer=%s expDate=%s, serial=%s %v",
				len(pemBytes), tuple.Issuer.ID(), tuple.ExpDate, tuple.SerialNum, err)
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			metrics.IncrCounter([]string{"ReconstructIssuerMetadata", "certParseError"}, 1)
			glog.Errorf("ParseCertificate failed, issuer=%s expDate=%s, serial=%s %v",
				tuple.Issuer.ID(), tuple.ExpDate, tuple.SerialNum, err)
			continue
		}
		metrics.MeasureSince([]string{"ReconstructIssuerMetadata", "DecodeParse"}, decodeTime)

		redisTime := time.Now()
		_, err = storageDB.GetIssuerMetadata(tuple.Issuer).Accumulate(cert)
		if err != nil {
			glog.Errorf("Accumulate failed issuer=%s expDate=%s, serial=%s %v",
				tuple.Issuer.ID(), tuple.ExpDate, tuple.SerialNum, err)
			continue
		}

		metrics.MeasureSince([]string{"ReconstructIssuerMetadata", "CacheInsertion"}, redisTime)

		serialProgressBar.IncrBy(1)
	}
}

func closeChanWhenWaitGroupCompletes(wait *sync.WaitGroup, channel chan<- storage.UniqueCertIdentifier) {
	wait.Wait()
	close(channel)
}

func main() {
	ctconfig.Init()

	// Long context is required for these operations
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	val, ok := os.LookupEnv("profile")
	if ok && val == "reprocess-known-certs" {
		glog.Info("Profiling to Stackdriver")
		if err := profiler.Start(profiler.Config{
			Service:        "reprocess-known-certs",
			ServiceVersion: "20191107",
			MutexProfiling: true,
		}); err != nil {
			glog.Errorf("Could not start profiler: %s", err)
		}
	}

	storageDB, extCache, backend := engine.GetConfiguredStorage(ctx, ctconfig)

	engine.PrepareTelemetry("reprocess-known-certs", ctconfig)
	defer glog.Flush()

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
		mpb.WithRefreshRate(refreshDur),
	)

	var count int64
	count, err = extCache.QueueLength(kIssuerExpdateQueueName)
	if err != nil {
		glog.Fatalf("Could not deterine queue length: %s", err)
	}

	if count > 0 {
		glog.Infof("Reprocess already in progress. %d ExpDate/Issuer tuples remain.",
			count)
	} else {
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

				if shouldProcess(expDate.ID(), issuer.ID()) {
					tuple := issuerDateTuple{expDate, issuer}

					count, err = extCache.Queue(kIssuerExpdateQueueName, tuple.String())
					if err != nil {
						glog.Fatalf("Could not enqueue: %s", err)
					}
				}
			}
		}
	}

	expIssuerProgressBar := display.AddBar(count,
		mpb.AppendDecorators(
			decor.Percentage(decor.WC{W: 6, C: decor.DidentRight}),
			decor.Name("ExpDate/Issuers"),
			decor.AverageETA(decor.ET_STYLE_GO, decor.WC{W: 14}),
			decor.CountersNoUnit("%d / %d", decor.WCSyncSpace),
		),
	)

	serialProgressBar := display.AddBar(math.MaxInt64,
		mpb.AppendDecorators(
			decor.Name("Unknown Certs Processed"),
			decor.CountersNoUnit("%d%.T", decor.WC{W: 8}), // %.T ignores the total
			decor.AverageSpeed(0, "%.1f/s", decor.WC{W: 8}),
			decor.Elapsed(decor.ET_STYLE_GO, decor.WCSyncSpace),
		),
	)

	// Exit signal, used by signals from the OS
	quitChan := make(chan struct{})

	// Nonbuffered channels so we can track completion without dataloss
	certSerialChan := make(chan storage.UniqueCertIdentifier)
	deduplicatedSerialChan := make(chan storage.UniqueCertIdentifier)

	var issuerDateWorkerWg sync.WaitGroup
	// Start the issuer/date workers, they populate certSerialChan
	for t := 0; t < *ctconfig.NumThreads; t++ {
		issuerDateWorkerWg.Add(1)
		// This, as the feeder, gets the quitchan
		go issuerAndDateWorker(ctx, &issuerDateWorkerWg, certSerialChan,
			quitChan, expIssuerProgressBar, backend, extCache)
	}
	go closeChanWhenWaitGroupCompletes(&issuerDateWorkerWg, certSerialChan)

	var deDupeWg sync.WaitGroup
	// Start the dedupe workers, they check the Redis cache and pass along
	// unknown certs into the outChan
	for t := 0; t < *ctconfig.NumThreads; t++ {
		deDupeWg.Add(1)
		go deduplicationWorker(&deDupeWg, certSerialChan, deduplicatedSerialChan,
			storageDB)
	}
	go closeChanWhenWaitGroupCompletes(&deDupeWg, deduplicatedSerialChan)

	// Start the Cert processors, that load PEMs from Firestore and handle them
	for t := 0; t < *ctconfig.NumProcessingThreads; t++ {
		topWg.Add(1)
		go certProcessingWorker(ctx, &topWg, deduplicatedSerialChan,
			serialProgressBar, storageDB, backend)
	}

	doneChan := make(chan storage.UniqueCertIdentifier)
	go closeChanWhenWaitGroupCompletes(&topWg, doneChan)

	select {
	case <-sigChan:
		glog.Infof("Signal caught, stopping threads at next opportunity.")
		close(quitChan)
	case <-doneChan:
		serialProgressBar.SetTotal(serialProgressBar.Current(), true)
	}
	topWg.Wait()
	deDupeWg.Wait()
	issuerDateWorkerWg.Wait()
	cancel()
	glog.Infof("Completed.")
}
