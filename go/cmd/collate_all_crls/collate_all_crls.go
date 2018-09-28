package main

import (
	"encoding/json"
	"flag"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/golang/glog"
	"github.com/jcjones/ct-mapreduce/config"
	"github.com/jcjones/ct-mapreduce/storage"
	"github.com/vbauerster/mpb"
	"github.com/vbauerster/mpb/decor"
)

var (
	outfile  = flag.String("out", "<stdout>", "output json dictionary of issues-to-CRLs")
	ctconfig = config.NewCTConfig()
)

type issuerCrlMap map[string]map[string]bool

func (self issuerCrlMap) Merge(other issuerCrlMap) {
	for issuer, crls := range other {
		selfCrls, pres := self[issuer]
		if !pres {
			selfCrls = make(map[string]bool)
		}
		for crl, _ := range crls {
			selfCrls[crl] = true
		}
		self[issuer] = selfCrls
	}
}

type metadataTuple struct {
	expDate string
	issuer  string
}

func issuerCrlWorker(wg *sync.WaitGroup, metaChan <-chan metadataTuple, quitChan <-chan struct{}, resultChan chan<- issuerCrlMap, progBar *mpb.Bar) {
	defer wg.Done()

	var lastTime time.Time

	issuerCrls := make(issuerCrlMap)

	for tuple := range metaChan {
		select {
		case <-quitChan:
			return
		default:
			meta := storage.GetIssuerMetadata(*ctconfig.CertPath, tuple.expDate, tuple.issuer, 0644)

			crls, prs := issuerCrls[tuple.issuer]
			if !prs {
				crls = make(map[string]bool)
			}
			for _, url := range meta.Metadata.Crls {
				crls[*url] = true
			}
			issuerCrls[tuple.issuer] = crls

			progBar.IncrBy(1, time.Since(lastTime))
			lastTime = time.Now()
		}
	}

	resultChan <- issuerCrls
}

func main() {
	var err error
	var storageDB storage.CertDatabase
	if ctconfig.CertPath != nil && len(*ctconfig.CertPath) > 0 {
		glog.Infof("Opening disk at %s", *ctconfig.CertPath)
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
	metaChan := make(chan metadataTuple, 16*1024*1024)

	// Handle signals from the OS
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, os.Interrupt)
	defer signal.Stop(sigChan)

	// Exit signal, used by signals from the OS
	quitChan := make(chan struct{})

	expDates, err := storageDB.ListExpirationDates(time.Now())
	if err != nil {
		glog.Fatalf("Could not list expiration dates", err)
	}

	var count int64
	for _, expDate := range expDates {
		issuers, err := storageDB.ListIssuersForExpirationDate(expDate)
		if err != nil {
			glog.Fatalf("Could not list issuers (%s) %s", expDate, err)
		}

		for _, issuer := range issuers {
			glog.V(1).Infof("%s/%s", expDate, issuer)
			select {
			case metaChan <- metadataTuple{expDate, issuer}:
				count = count + 1
			default:
				glog.Fatalf("Channel overflow. Aborting at %s %s", expDate, issuer)
			}
		}
	}

	// Signal that was the last work
	close(metaChan)

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

	resultChan := make(chan issuerCrlMap, *ctconfig.NumThreads)

	// Start the workers
	for t := 0; t < *ctconfig.NumThreads; t++ {
		wg.Add(1)
		go issuerCrlWorker(&wg, metaChan, quitChan, resultChan, progressBar)
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
		close(resultChan)
	}

	// Take all worker results and merge them into one JSON structure
	mergedCrls := make(issuerCrlMap)
	for mapPart := range resultChan {
		mergedCrls.Merge(mapPart)
	}

	crls := make(map[string][]string)
	for issuer, crlMap := range mergedCrls {
		urls := make([]string, len(crlMap))
		i := 0
		for k := range crlMap {
			urls[i] = k
			i++
		}
		crls[issuer] = urls
	}

	if *outfile == "<stdout>" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", " ")
		if err = enc.Encode(crls); err != nil {
			glog.Fatal(err)
		}
		return
	}

	f, err := os.OpenFile(*outfile, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		glog.Fatal(err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	if err = enc.Encode(crls); err != nil {
		glog.Fatal(err)
	}
}
