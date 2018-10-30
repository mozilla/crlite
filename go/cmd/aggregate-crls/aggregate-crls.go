package main

import (
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
	crlpath  = flag.String("crls", "<path>", "root of folders of the form /<path>/<issuer> containing .crl files to be updated")
	outpath  = flag.String("out", "<path>", "output folder of revoked serial files of the form <issuer>.revoked")
	ctconfig = config.NewCTConfig()

	illegalPath = regexp.MustCompile(`[^[:alnum:]\~\-\./]`)

	allowableAgeOfLocalCRL, _ = time.ParseDuration("336h")
)

func makeFilenameFromUrl(crlUrl url.URL) string {
	filename := fmt.Sprintf("%s-%s", crlUrl.Hostname(), path.Base(crlUrl.Path))
	filename = strings.ToLower(filename)
	filename = illegalPath.ReplaceAllString(filename, "")
	if strings.HasSuffix(filename, ".crl") == false {
		filename = fmt.Sprintf("%s.crl", filename)
	}
	return filename
}

func findCrlWorker(wg *sync.WaitGroup, metaChan <-chan types.MetadataTuple, quitChan <-chan struct{}, resultChan chan<- types.IssuerCrlMap, progBar *mpb.Bar) {
	defer wg.Done()

	lastTime := time.Now()

	issuerCrls := make(types.IssuerCrlMap)

	for tuple := range metaChan {
		select {
		case <-quitChan:
			return
		default:
			meta := storage.GetIssuerMetadata(*ctconfig.CertPath, tuple.ExpDate, tuple.Issuer, permMode)

			crls, prs := issuerCrls[tuple.Issuer]
			if !prs {
				crls = make(map[string]bool)
			}
			for _, url := range meta.Metadata.Crls {
				crls[*url] = true
			}
			issuerCrls[tuple.Issuer] = crls

			progBar.IncrBy(1, time.Since(lastTime))
			lastTime = time.Now()
		}
	}

	resultChan <- issuerCrls
}

func crlFetchWorker(wg *sync.WaitGroup, display *mpb.Progress, crlsChan <-chan types.IssuerCrlUrls, quitChan <-chan struct{}, resultChan chan<- types.IssuerCrlPaths, progBar *mpb.Bar) {
	defer wg.Done()

	lastTime := time.Now()

	for tuple := range crlsChan {
		paths := make([]string, 0)

		for _, crlUrl := range tuple.Urls {
			filename := makeFilenameFromUrl(crlUrl)
			err := os.MkdirAll(filepath.Join(*crlpath, tuple.Issuer), permModeDir)
			if err != nil {
				glog.Warningf("Couldn't make directory: %s", err)
				continue
			}

			path := filepath.Join(*crlpath, tuple.Issuer, filename)

			err = downloader.DownloadFileSync(display, crlUrl, path)
			if err != nil {
				glog.Warningf("[%s] Could not download %s to %s", tuple.Issuer, crlUrl.String(), path)
				// Does it already exist on disk? If so, use that version and not die.

				_, localDate, err := downloader.GetSizeAndDateOfFile(path)
				if err != nil {
					glog.Warningf("[%s] Could not download, and no local file", crlUrl.String())
					// panic("Not handling download failure without a local copy")
					continue
				}

				age := time.Now().Sub(localDate)

				if age > allowableAgeOfLocalCRL {
					glog.Warningf("[%s] Could not download, and out of date local file. Age: %s", crlUrl.String(), age.String())
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

func processCRL(aPath string, aRevoked *storage.KnownCertificates, aIssuerCert *x509.Certificate) {
	glog.Infof("[%s] Proesssing CRL", aPath)
	crlBytes, err := ioutil.ReadFile(aPath)
	if err != nil {
		glog.Warningf("[%s] Error reading: %s", aPath, err)
		return
	}

	crl, err := x509.ParseCRL(crlBytes)
	if err != nil {
		glog.Warningf("[%s] Error parsing: %s", aPath, err)
		return
	}

	if err = aIssuerCert.CheckCRLSignature(crl); err != nil {
		glog.Errorf("[%s] Invalid signature on CRL: %s", aPath, err)
		return
	}

	if crl.HasExpired(time.Now()) {
		glog.Warningf("[%s] CRL is expired, but proceeding anyway", aPath)
	}

	for _, ent := range crl.TBSCertList.RevokedCertificates {
		newRevocation, err := aRevoked.WasUnknown(ent.SerialNumber)
		if err != nil {
			glog.Warningf("[%s] Error recording revocation [%v]: %s", aPath, ent.SerialNumber, err)
		}
		if newRevocation {
			glog.V(2).Infof("[%s] Newly seen revocation: [%v]", aPath, ent.SerialNumber)
		}
	}
}

func aggregateCRLWorker(wg *sync.WaitGroup, mozIssuers *rootprogram.MozIssuers, outPath string, workChan <-chan types.IssuerCrlPaths, quitChan <-chan struct{}, progBar *mpb.Bar) {
	defer wg.Done()

	lastTime := time.Now()

	for tuple := range workChan {
		outfile := filepath.Join(outPath, fmt.Sprintf("%s.revoked", tuple.Issuer))

		revokedCerts := storage.NewKnownCertificates(outfile, 0644)
		if err := revokedCerts.Load(); err != nil {
			glog.Infof("Making new revocation storage file %s", outfile)
		}

		for _, crlPath := range tuple.CrlPaths {
			select {
			case <-quitChan:
				if err := revokedCerts.Save(); err != nil {
					glog.Fatalf("[%s] Could not save revoked certificates file: %s", outfile, err)
				}
				return
			default:
				cert, err := mozIssuers.GetCertificateForIssuer(tuple.Issuer)
				if err != nil {
					glog.Fatalf("[%s] Could not find certificate for issuer: %s", tuple.Issuer, err)
				}

				processCRL(crlPath, revokedCerts, cert)
			}
		}

		if err := revokedCerts.Save(); err != nil {
			glog.Fatalf("[%s] Could not save revoked certificates file: %s", outfile, err)
		}

		progBar.IncrBy(1, time.Since(lastTime))
		lastTime = time.Now()
	}
}

func identifyCrlsByIssuer(display *mpb.Progress, mozissuers *rootprogram.MozIssuers, storageDB storage.CertDatabase, sigChan <-chan os.Signal) types.IssuerCrlMap {
	var wg sync.WaitGroup

	metaChan := make(chan types.MetadataTuple, 16*1024*1024)

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
			if !mozissuers.IsIssuerInProgram(issuer) {
				continue
			}

			select {
			case metaChan <- types.MetadataTuple{expDate, issuer}:
				count = count + 1
			default:
				glog.Fatalf("Channel overflow. Aborting at %s %s", expDate, issuer)
			}
		}
	}

	// Signal that was the last work
	close(metaChan)

	// Exit signal, used by signals from the OS
	quitChan := make(chan struct{})

	progressBar := display.AddBar(count,
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
		go findCrlWorker(&wg, metaChan, quitChan, resultChan, progressBar)
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

func downloadCRLs(display *mpb.Progress, issuerToUrls types.IssuerCrlMap, sigChan <-chan os.Signal) (<-chan types.IssuerCrlPaths, int64) {
	var wg sync.WaitGroup

	// Exit signal, used by signals from the OS
	quitChan := make(chan struct{})

	crlChan := make(chan types.IssuerCrlUrls, 16*1024*1024)
	var count int64
	for issuer, crlMap := range issuerToUrls {
		var urls []url.URL

		for iUrl := range crlMap {
			urlObj, err := url.Parse(iUrl)
			if err != nil {
				glog.Warningf("Ignoring URL %s: %s", iUrl, err)
				continue
			}
			urls = append(urls, *urlObj)
		}

		if len(urls) > 0 {
			crlChan <- types.IssuerCrlUrls{
				Issuer: issuer,
				Urls:   urls,
			}
			count = count + 1
		}
	}
	close(crlChan)

	progressBar := display.AddBar(count,
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
		go crlFetchWorker(&wg, display, crlChan, quitChan, resultChan, progressBar)
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

func aggregateCRLs(display *mpb.Progress, mozIssuers *rootprogram.MozIssuers, count int64, crlPaths <-chan types.IssuerCrlPaths, outPath string, sigChan <-chan os.Signal) {
	var wg sync.WaitGroup

	// Exit signal, used by signals from the OS
	quitChan := make(chan struct{})

	progressBar := display.AddBar(count,
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
		go aggregateCRLWorker(&wg, mozIssuers, outPath, crlPaths, quitChan, progressBar)
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
	var err error
	var storageDB storage.CertDatabase
	if ctconfig.CertPath != nil && len(*ctconfig.CertPath) > 0 {
		glog.Infof("Opening disk at %s", *ctconfig.CertPath)
		storageDB, err = storage.NewDiskDatabase(*ctconfig.CacheSize, *ctconfig.CertPath, permMode)
		if err != nil {
			glog.Fatalf("Unable to open Certificate Path: %s: %s", ctconfig.CertPath, err)
		}
	}

	if storageDB == nil || *outpath == "<path>" || *crlpath == "<path>" {
		ctconfig.Usage()
		os.Exit(2)
	}

	if err := os.MkdirAll(*outpath, permModeDir); err != nil {
		glog.Fatalf("Unable to make the output directory: %s", err)
	}
	if err := os.MkdirAll(*crlpath, permModeDir); err != nil {
		glog.Fatalf("Unable to make the CRL directory: %s", err)
	}

	mozIssuers := rootprogram.NewMozillaIssuers()
	if *ccadb != "<path>" {
		err = mozIssuers.LoadFromDisk(*ccadb)
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

	mergedCrls := identifyCrlsByIssuer(display, mozIssuers, storageDB, sigChan)
	if mergedCrls == nil {
		return
	}

	crlPaths, count := downloadCRLs(display, mergedCrls, sigChan)

	aggregateCRLs(display, mozIssuers, count, crlPaths, *outpath, sigChan)
}
