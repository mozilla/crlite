package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/jcjones/ct-mapreduce/config"
	"github.com/jcjones/ct-mapreduce/engine"
	"github.com/jcjones/ct-mapreduce/storage"
	"github.com/mozilla/crlite/go"
	"github.com/mozilla/crlite/go/downloader"
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
	crlpath  = flag.String("crlpath", "<path>", "root of folders of the form /<path>/<issuer> containing .crl files to be updated")
	outpath  = flag.String("outpath", "<path>", "output folder of revoked serial files of the form <issuer>.revoked")
	ctconfig = config.NewCTConfig()

	illegalPath = regexp.MustCompile(`[^[:alnum:]\~\-\./]`)

	allowableAgeOfLocalCRL, _ = time.ParseDuration("336h")
)

type AggregateEngine struct {
	loadStorageDB storage.CertDatabase
	saveStorage   storage.StorageBackend
	remoteCache   storage.RemoteCache

	issuers *rootprogram.MozIssuers
	display *mpb.Progress
}

func makeFilenameFromUrl(crlUrl url.URL) string {
	filename := fmt.Sprintf("%s-%s", crlUrl.Hostname(), path.Base(crlUrl.Path))
	filename = strings.ToLower(filename)
	filename = illegalPath.ReplaceAllString(filename, "")

	hash := sha256.Sum256([]byte(crlUrl.String()))

	filename = strings.TrimSuffix(filename, ".crl")
	filename = fmt.Sprintf("%s-%s.crl", filename, hex.EncodeToString(hash[:8]))
	return filename
}

func (ae *AggregateEngine) findCrlWorker(wg *sync.WaitGroup, metaChan <-chan types.MetadataTuple, quitChan <-chan struct{}, resultChan chan<- types.IssuerCrlMap, progBar *mpb.Bar) {
	defer wg.Done()

	lastTime := time.Now()

	issuerCrls := make(types.IssuerCrlMap)

	for tuple := range metaChan {
		select {
		case <-quitChan:
			return
		default:
			meta := ae.loadStorageDB.GetIssuerMetadata(tuple.Issuer)

			crls, prs := issuerCrls[tuple.Issuer.ID()]
			if !prs {
				crls = make(map[string]bool)
			}
			for _, url := range meta.CRLs() {
				crls[url] = true
			}
			issuerCrls[tuple.Issuer.ID()] = crls

			progBar.IncrBy(1, time.Since(lastTime))
			lastTime = time.Now()
		}
	}

	resultChan <- issuerCrls
}

func (ae *AggregateEngine) crlFetchWorker(wg *sync.WaitGroup, crlsChan <-chan types.IssuerCrlUrls, quitChan <-chan struct{}, resultChan chan<- types.IssuerCrlPaths, progBar *mpb.Bar) {
	defer wg.Done()

	lastTime := time.Now()

	for tuple := range crlsChan {
		paths := make([]string, 0)

		for _, crlUrl := range tuple.Urls {
			filename := makeFilenameFromUrl(crlUrl)
			err := os.MkdirAll(filepath.Join(*crlpath, tuple.Issuer.ID()), permModeDir)
			if err != nil {
				glog.Warningf("Couldn't make directory: %s", err)
				continue
			}

			path := filepath.Join(*crlpath, tuple.Issuer.ID(), filename)

			err = downloader.DownloadFileSync(ae.display, crlUrl, path)
			if err != nil {
				glog.Warningf("[%s] Could not download %s to %s: %s", tuple.Issuer.ID(), crlUrl.String(), path, err)
				// Does it already exist on disk? If so, use that version and not die.

				_, localDate, err := downloader.GetSizeAndDateOfFile(path)
				if err != nil {
					glog.Errorf("[%s] Could not download, and no local file, will not be populating the revocations", crlUrl.String())
					// panic("Not handling download failure without a local copy")
					continue
				}

				age := time.Now().Sub(localDate)

				if age > allowableAgeOfLocalCRL {
					glog.Errorf("[%s] Could not download, and out of date local file, will not be populating the revocations. Age: %s", crlUrl.String(), age.String())
					// panic("Not handling download failure without an up-to-date local copy")
					continue
				}
			}

			select {
			case <-quitChan:
				return
			default:
				paths = append(paths, path)
			}
		}

		resultChan <- types.IssuerCrlPaths{
			Issuer:   tuple.Issuer,
			CrlPaths: paths,
		}

		progBar.IncrBy(1, time.Since(lastTime))
		lastTime = time.Now()
	}
}

func processCRL(aPath string, aRevoked *types.SerialSet, aIssuerCert *x509.Certificate) bool {
	glog.Infof("[%s] Proesssing CRL", aPath)
	crlBytes, err := ioutil.ReadFile(aPath)
	if err != nil {
		glog.Errorf("[%s] Error reading CRL, will not process revocations: %s", aPath, err)
		return false
	}

	crl, err := x509.ParseCRL(crlBytes)
	if err != nil {
		glog.Errorf("[%s] Error parsing, will not process revocations: %s", aPath, err)
		return false
	}

	if err = aIssuerCert.CheckCRLSignature(crl); err != nil {
		glog.Errorf("[%s] Invalid signature on CRL, will not process revocations: %s", aPath, err)
		return false
	}

	if crl.HasExpired(time.Now()) {
		glog.Warningf("[%s] CRL is expired, but proceeding anyway", aPath)
	}

	// Decode the raw DER serial numbers
	revokedList, err := types.DecodeRawTBSCertList(crl.TBSCertList.Raw)
	if err != nil {
		glog.Warningf("[%s] CRL list couldn't be decoded: %s", aPath, err)
		return false
	}

	for _, ent := range revokedList.RevokedCertificates {
		serial := storage.NewSerialFromBytes(ent.SerialNumber.Bytes)
		newRevocation := aRevoked.Add(serial)
		if newRevocation {
			glog.V(2).Infof("[%s] Newly seen revocation: [%v]", aPath, ent.SerialNumber)
		}
	}
	return true
}

func (ae *AggregateEngine) aggregateCRLWorker(wg *sync.WaitGroup, outPath string, workChan <-chan types.IssuerCrlPaths, quitChan <-chan struct{}, progBar *mpb.Bar) {
	defer wg.Done()

	for tuple := range workChan {
		cycleTime := time.Now()

		issuerEnrolled := false
		serials := types.NewSerialSet()

		for _, crlPath := range tuple.CrlPaths {
			select {
			case <-quitChan:
				return
			default:
				cert, err := ae.issuers.GetCertificateForIssuer(tuple.Issuer)
				if err != nil {
					glog.Fatalf("[%s] Could not find certificate for issuer: %s", tuple.Issuer.ID(), err)
				}

				if processCRL(crlPath, serials, cert) {
					// Issuer is considered enrolled if at least one CRL processed successfully
					issuerEnrolled = true
					ae.issuers.Enroll(tuple.Issuer)
				}
			}
		}

		if issuerEnrolled {
			if err := ae.saveStorage.StoreKnownCertificateList(storage.Revoked, tuple.Issuer, serials.List()); err != nil {
				glog.Fatalf("[%s] Could not save revoked certificates file: %s", tuple.Issuer.ID(), err)
			}
		} else {
			glog.Infof("Issuer %s not enrolled", tuple.Issuer.ID())
		}

		progBar.IncrBy(1, time.Since(cycleTime))
	}
}

func (ae *AggregateEngine) identifyCrlsByIssuer(sigChan <-chan os.Signal) types.IssuerCrlMap {
	var wg sync.WaitGroup

	metaChan := make(chan types.MetadataTuple, 16*1024*1024)

	expDates, err := ae.loadStorageDB.ListExpirationDates(time.Now())
	if err != nil {
		glog.Fatalf("Could not list expiration dates: %s", err)
	}

	var count int64
	for _, expDate := range expDates {
		issuers, err := ae.loadStorageDB.ListIssuersForExpirationDate(expDate)
		if err != nil {
			glog.Fatalf("Could not list issuers (%s) %s", expDate, err)
		}

		for _, issuer := range issuers {
			if !ae.issuers.IsIssuerInProgram(issuer) {
				continue
			}

			select {
			case metaChan <- types.MetadataTuple{ExpDate: expDate, Issuer: issuer}:
				count = count + 1
			default:
				glog.Fatalf("Channel overflow. Aborting at %s %s", expDate, issuer.ID())
			}
		}
	}

	// Signal that was the last work
	close(metaChan)

	// Exit signal, used by signals from the OS
	quitChan := make(chan struct{})

	progressBar := ae.display.AddBar(count,
		mpb.PrependDecorators(
			decor.Name("Identify CRLs"),
		),
		mpb.AppendDecorators(
			decor.Percentage(),
			decor.Name(""),
			decor.EwmaETA(decor.ET_STYLE_GO, 16, decor.WC{W: 14}),
			decor.CountersNoUnit("%d / %d", decor.WCSyncSpace),
		),
	)

	resultChan := make(chan types.IssuerCrlMap, *ctconfig.NumThreads)

	// Start the workers
	for t := 0; t < *ctconfig.NumThreads; t++ {
		wg.Add(1)
		go ae.findCrlWorker(&wg, metaChan, quitChan, resultChan, progressBar)
	}

	// Set up a notifier for the workers closing
	doneChan := make(chan bool)
	go func(wait *sync.WaitGroup) {
		wait.Wait()
		doneChan <- true
	}(&wg)

	select {
	case <-sigChan:
		glog.Infof("Signal caught, stopping threads at next opportunity.")
		quitChan <- struct{}{}
		return nil
	case <-doneChan:
		close(resultChan)
	}

	// Take all worker results and merge them into one JSON structure
	mergedCrls := make(types.IssuerCrlMap)
	for mapPart := range resultChan {
		mergedCrls.Merge(mapPart)
	}

	return mergedCrls
}

func (ae *AggregateEngine) downloadCRLs(issuerToUrls types.IssuerCrlMap, sigChan <-chan os.Signal) (<-chan types.IssuerCrlPaths, int64) {
	var wg sync.WaitGroup

	// Exit signal, used by signals from the OS
	quitChan := make(chan struct{})

	crlChan := make(chan types.IssuerCrlUrls, 16*1024*1024)
	var count int64
	for issuer, crlMap := range issuerToUrls {
		var urls []url.URL

		for iUrl := range crlMap {
			urlObj, err := url.Parse(strings.TrimSpace(iUrl))
			if err != nil {
				glog.Warningf("Ignoring URL %s: %s", iUrl, err)
				continue
			}
			urls = append(urls, *urlObj)
		}

		if len(urls) > 0 {
			crlChan <- types.IssuerCrlUrls{
				Issuer: storage.NewIssuerFromString(issuer),
				Urls:   urls,
			}
			count = count + 1
		}
	}
	close(crlChan)

	progressBar := ae.display.AddBar(count,
		mpb.PrependDecorators(
			decor.Name("Download CRLs"),
		),
		mpb.AppendDecorators(
			decor.Percentage(),
			decor.Name(""),
			decor.EwmaETA(decor.ET_STYLE_GO, 4, decor.WC{W: 14}),
			decor.CountersNoUnit("%d / %d", decor.WCSyncSpace),
		),
	)

	resultChan := make(chan types.IssuerCrlPaths, count)

	// Start the workers
	for t := 0; t < *ctconfig.NumThreads; t++ {
		wg.Add(1)
		go ae.crlFetchWorker(&wg, crlChan, quitChan, resultChan, progressBar)
	}

	// Set up a notifier for the workers closing
	doneChan := make(chan bool)
	go func(wait *sync.WaitGroup) {
		wait.Wait()
		doneChan <- true
	}(&wg)

	select {
	case <-sigChan:
		glog.Infof("Signal caught, stopping threads at next opportunity.")
		quitChan <- struct{}{}
		return nil, 0
	case <-doneChan:
		close(resultChan)
	}

	return resultChan, count
}

func (ae *AggregateEngine) aggregateCRLs(count int64, crlPaths <-chan types.IssuerCrlPaths, outPath string, sigChan <-chan os.Signal) {
	var wg sync.WaitGroup

	// Exit signal, used by signals from the OS
	quitChan := make(chan struct{})

	progressBar := ae.display.AddBar(count,
		mpb.PrependDecorators(
			decor.Name("Aggregate CRLs"),
		),
		mpb.AppendDecorators(
			decor.Percentage(),
			decor.Name(""),
			decor.EwmaETA(decor.ET_STYLE_GO, 4, decor.WC{W: 14}),
			decor.CountersNoUnit("%d / %d", decor.WCSyncSpace),
		),
	)

	// Start the workers
	for t := 0; t < *ctconfig.NumThreads; t++ {
		wg.Add(1)
		go ae.aggregateCRLWorker(&wg, outPath, crlPaths, quitChan, progressBar)
	}

	// Set up a notifier for the workers closing
	doneChan := make(chan bool)
	go func(wait *sync.WaitGroup) {
		wait.Wait()
		doneChan <- true
	}(&wg)

	select {
	case <-sigChan:
		glog.Infof("Signal caught, stopping threads at next opportunity.")
		quitChan <- struct{}{}
		return
	case <-doneChan:
		glog.Infof("Completed.")
	}
}

func main() {
	ctconfig.Init()
	storageDB, remoteCache, _ := engine.GetConfiguredStorage(ctconfig)

	if *outpath == "<path>" {
		glog.Error("outpath is not set")
		ctconfig.Usage()
		os.Exit(2)
	}

	if *crlpath == "<path>" {
		glog.Error("crlpath is not set")
		ctconfig.Usage()
		os.Exit(2)
	}

	if err := os.MkdirAll(*outpath, permModeDir); err != nil {
		glog.Fatalf("Unable to make the output directory: %s", err)
	}
	if err := os.MkdirAll(*crlpath, permModeDir); err != nil {
		glog.Fatalf("Unable to make the CRL directory: %s", err)
	}

	engine.PrepareTelemetry("aggregate-crls", ctconfig)

	saveBackend := storage.NewLocalDiskBackend(permMode, *outpath)

	var err error
	mozIssuers := rootprogram.NewMozillaIssuers()
	if *inccadb != "<path>" {
		err = mozIssuers.LoadFromDisk(*inccadb)
	} else {
		err = mozIssuers.Load()
	}

	if err != nil {
		glog.Fatalf("Unable to load the Mozilla issuers: %s", err)
	}

	// Handle signals from the OS
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, os.Interrupt)
	defer signal.Stop(sigChan)

	display := mpb.New()

	ae := AggregateEngine{
		loadStorageDB: storageDB,
		saveStorage:   saveBackend,
		remoteCache:   remoteCache,
		issuers:       mozIssuers,
		display:       display,
	}

	mergedCrls := ae.identifyCrlsByIssuer(sigChan)
	if mergedCrls == nil {
		return
	}

	crlPaths, count := ae.downloadCRLs(mergedCrls, sigChan)

	ae.aggregateCRLs(count, crlPaths, *outpath, sigChan)
	issuersPath := filepath.Join(*outpath, "knownIssuers.json")
	if err = mozIssuers.SaveIssuersList(issuersPath); err != nil {
		glog.Fatalf("Unable to save the crlite-informed intermediate issuers: %s", err)
	}
}
