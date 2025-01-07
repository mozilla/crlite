package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/golang/glog"
	"github.com/mozilla/crlite/go"
	"github.com/mozilla/crlite/go/config"
	"github.com/mozilla/crlite/go/engine"
	"github.com/mozilla/crlite/go/rootprogram"
	"github.com/mozilla/crlite/go/storage"
)

const (
	permMode    = 0644
	permModeDir = 0755
)

var (
	enrolledpath = flag.String("enrolledpath", "<path>", "input enrolled issuers JSON")
	knownpath    = flag.String("knownpath", "<dir>", "output directory for <issuer> files")
	ctlogspath   = flag.String("ctlogspath", "<path>", "output file for ct-log JSON")
	ctconfig     = config.NewCTConfig()
)

type knownWorkUnit struct {
	issuer   types.Issuer
	issuerDN string
	expDates []types.ExpDate
}

type knownWorker struct {
	savePath    string
	remoteCache storage.RemoteCache
}

func (kw knownWorker) run(ctx context.Context, wg *sync.WaitGroup, workChan <-chan knownWorkUnit) {
	defer wg.Done()

	err := os.MkdirAll(kw.savePath, permModeDir)
	if err != nil && !os.IsExist(err) {
		glog.Fatalf("Could not make directory %s: %s", kw.savePath, err)
	}

	for tuple := range workChan {
		// Wrap in anonymous function to defer a writer.Flush & fd.Close per work unit
		func() {
			path := filepath.Join(kw.savePath, tuple.issuer.ID())
			fd, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, permMode)
			if err != nil {
				glog.Fatalf("[%s] Could not open known certificates file: %s", tuple.issuer.ID(), err)
			}
			defer fd.Close()

			writer := bufio.NewWriter(fd)
			defer writer.Flush()

			var serialCount uint64

			for _, expDate := range tuple.expDates {
				select {
				case <-ctx.Done():
					glog.Warningf("Signal on worker quit channel, quitting (count=%d).", serialCount)
					return
				default:
				}

				if expDate.IsExpiredAt(time.Now()) {
					if glog.V(1) {
						glog.Warningf("Date %s is expired now, skipping (issuer=%s)", expDate, tuple.issuer.ID())
					}
					continue
				}

				// Sharded by expiry date, so this should be fairly small.
				known := storage.NewSerialCacheReader(expDate, tuple.issuer, kw.remoteCache)

				knownSet := known.Known()
				knownSetLen := uint64(len(knownSet))

				if knownSetLen == 0 {
					// This is almost certainly due to an hour-rollover since the loader ran, and expired all the next hour's
					// certs.
					glog.Warningf("No cached certificates for issuer=%s (%s) expDate=%s, but the loader thought there should be."+
						" (current count this worker=%d)", tuple.issuerDN, tuple.issuer.ID(), expDate, serialCount)
				}

				serialCount += knownSetLen
				// Write the common (truncated) expiry date for this collection of serial numbers
				// as a zero-padded 16 digit hex string. The date is encoded as a unix timestamp.
				// Expiry date rows are prefixed by "@" to distinguish them from a serial numbers.
				_, err := writer.WriteString(fmt.Sprintf("@%016x\n", expDate.Unix()))
				if err != nil {
					glog.Fatalf("[%s] Could not write serials: %s", tuple.issuer.ID(), err)
				}
				for _, s := range knownSet {
					_, err := writer.WriteString(s.HexString())
					if err != nil {
						glog.Fatalf("[%s] Could not write serials: %s", tuple.issuer.ID(), err)
					}
					err = writer.WriteByte('\n')
					if err != nil {
						glog.Fatalf("[%s] Could not write serials: %s", tuple.issuer.ID(), err)
					}
				}
			}
			glog.Infof("[%s] %d total known serials for %s (shards=%d)", tuple.issuer.ID(),
				serialCount, tuple.issuerDN, len(tuple.expDates))
		}()

		select {
		case <-ctx.Done():
			return
		default:
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
	ctx, cancelMain := context.WithCancel(ctx)

	// Try to handle SIGINT and SIGTERM gracefully
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	defer close(sigChan)
	go func() {
		sig := <-sigChan
		glog.Infof("Signal caught: %s..", sig)
		cancelMain()
		signal.Stop(sigChan) // Restore default behavior
	}()

	storageDB, remoteCache := engine.GetConfiguredStorage(ctx, ctconfig)
	defer glog.Flush()

	checkPathArg(*enrolledpath, "enrolledpath", ctconfig)
	checkPathArg(*knownpath, "knownpath", ctconfig)
	checkPathArg(*ctlogspath, "ctlogspath", ctconfig)

	if err := os.MkdirAll(*knownpath, permModeDir); err != nil {
		glog.Fatalf("Unable to make the output directory: %s", err)
	}

	engine.PrepareTelemetry("aggregate-known", ctconfig)

	mozIssuers := rootprogram.NewMozillaIssuers()
	if err := mozIssuers.LoadEnrolledIssuers(*enrolledpath); err != nil {
		glog.Fatalf("Failed to load enrolled issuers from disk: %s", err)
	}

	glog.Infof("%d issuers loaded", len(mozIssuers.GetIssuers()))

	// Save the CT log metadata before pulling known certs. It's OK
	// if the known certs are a superset of the certs described
	// by the metadata, but the other way around is dangerous.
	glog.Infof("Saving CT Log metadata")
	logList, err := storageDB.GetCTLogsFromCache()
	if err != nil {
		glog.Fatal(err)
	}

	ctLogFD, err := os.OpenFile(*ctlogspath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		glog.Fatalf("Error opening %s: %s", *ctlogspath, err)
	}

	enc := json.NewEncoder(ctLogFD)
	if err := enc.Encode(logList); err != nil {
		glog.Fatalf("Error marshaling ct-logs list %s: %s", *ctlogspath, err)
	}
	ctLogFD.Close()

	glog.Infof("Listing issuers and their expiration dates...")
	issuerList, err := storageDB.GetIssuerAndDatesFromCache()
	if err != nil {
		glog.Fatal(err)
	}

	var count int64
	for _, iObj := range issuerList {
		if mozIssuers.IsIssuerInProgram(iObj.Issuer) {
			count = count + int64(len(iObj.ExpDates))
		}
	}

	workChan := make(chan knownWorkUnit, count)
	for _, iObj := range issuerList {
		if !mozIssuers.IsIssuerInProgram(iObj.Issuer) {
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

	glog.Infof("Starting worker processes to handle %d work units", count)

	var wg sync.WaitGroup

	// Start the workers
	for t := 0; t < *ctconfig.NumThreads; t++ {
		wg.Add(1)
		worker := knownWorker{
			savePath:    *knownpath,
			remoteCache: remoteCache,
		}
		go worker.run(ctx, &wg, workChan)
	}

	wg.Wait()
}
