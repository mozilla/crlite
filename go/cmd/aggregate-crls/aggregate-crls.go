package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
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
	"github.com/google/certificate-transparency-go/x509/pkix"
	"github.com/jcjones/ct-mapreduce/config"
	"github.com/jcjones/ct-mapreduce/engine"
	"github.com/jcjones/ct-mapreduce/storage"
	"github.com/mozilla/crlite/go"
	"github.com/mozilla/crlite/go/downloader"
	"github.com/mozilla/crlite/go/rootprogram"
	"github.com/vbauerster/mpb/v5"
	"github.com/vbauerster/mpb/v5/decor"
)

const (
	permMode    = 0644
	permModeDir = 0755
)

var (
	inccadb      = flag.String("ccadb", "<path>", "input CCADB CSV path")
	crlpath      = flag.String("crlpath", "<path>", "root of folders of the form /<path>/<issuer> containing .crl files to be updated")
	revokedpath  = flag.String("revokedpath", "<path>", "output folder of revoked serial files of the form <issuer>")
	enrolledpath = flag.String("enrolledpath", "<path>", "output JSON file of issuers with their enrollment status")
	nobars       = flag.Bool("nobars", false, "disable display of download bars")
	ctconfig     = config.NewCTConfig()

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

func (ae *AggregateEngine) findCrlWorker(ctx context.Context, wg *sync.WaitGroup,
	issuerChan <-chan storage.Issuer, resultChan chan<- types.IssuerCrlMap, progBar *mpb.Bar) {
	defer wg.Done()

	issuerCrls := make(types.IssuerCrlMap)

	for issuer := range issuerChan {
		select {
		case <-ctx.Done():
			return
		default:
			meta := ae.loadStorageDB.GetIssuerMetadata(issuer)

			crls, prs := issuerCrls[issuer.ID()]
			if !prs {
				crls = make(map[string]bool)
			}

			crlSet := meta.CRLs()

			if len(crlSet) == 0 {
				if ae.issuers.IsIssuerInProgram(issuer) {
					issuerSubj, err := ae.issuers.GetSubjectForIssuer(issuer)
					if err != nil {
						glog.Warningf("No known CRLs and couldn't get subject for issuer=%s that is in the root program: %s",
							issuer.ID(), err)
					} else {
						glog.Infof("No known CRLs for issuer=%s (%s) in the root program. Not enrolling into CRLite.",
							issuer.ID(), issuerSubj)
					}
				}
			}

			for _, url := range crlSet {
				crls[url] = true
			}
			issuerCrls[issuer.ID()] = crls

			progBar.Increment()
		}
	}

	resultChan <- issuerCrls
}

func (ae *AggregateEngine) crlFetchWorkerProcessOne(ctx context.Context, crlUrl url.URL, issuer storage.Issuer) (string, error) {
	err := os.MkdirAll(filepath.Join(*crlpath, issuer.ID()), permModeDir)
	if err != nil {
		glog.Warningf("Couldn't make directory: %s", err)
		return "", err
	}

	filename := makeFilenameFromUrl(crlUrl)
	tmpPath := filepath.Join(*crlpath, issuer.ID(), filename+".tmp")
	finalPath := filepath.Join(*crlpath, issuer.ID(), filename)

	err = downloader.DownloadFileSync(ctx, ae.display, crlUrl, tmpPath, 3)
	if err != nil {
		glog.Warningf("[%s] Could not download %s to %s: %s", issuer.ID(), crlUrl.String(),
			tmpPath, err)
	} else {
		// Validate the file and move it to the finalPath
		cert, err := ae.issuers.GetCertificateForIssuer(issuer)
		if err != nil {
			glog.Fatalf("[%s] Could not find certificate for issuer: %s", issuer.ID(), err)
		}

		_, err = verifyCRL(tmpPath, cert, finalPath)
		if err != nil {
			glog.Warningf("[%s] Failed to verify, keeping existing: %s", issuer.ID(), err)
			err = os.Remove(tmpPath)
			if err != nil {
				glog.Warningf("[%s] Failed to remove invalid tmp file %s: %s", issuer.ID(), tmpPath, err)
			}
		} else {
			err = os.Rename(tmpPath, finalPath)
			if err != nil {
				glog.Errorf("[%s] Couldn't rename %s to %s: %s", issuer.ID(), tmpPath, finalPath, err)
			}
		}
	}

	// Ensure the final path is acceptable
	localSize, localDate, err := downloader.GetSizeAndDateOfFile(finalPath)
	if err != nil {
		glog.Errorf("[%s] Could not download, and no local file, will not be populating the "+
			"revocations: %s", crlUrl.String(), err)
		return "", err
	}

	age := time.Now().Sub(localDate)

	if age > allowableAgeOfLocalCRL {
		glog.Warningf("[%s] CRL appears very old. Age: %s", crlUrl.String(), age)
	}

	glog.Infof("[%s] Updated CRL %s (path=%s) (sz=%d) (age=%s)", issuer.ID(), crlUrl.String(),
		finalPath, localSize, age)

	return finalPath, nil
}

func (ae *AggregateEngine) crlFetchWorker(ctx context.Context, wg *sync.WaitGroup,
	crlsChan <-chan types.IssuerCrlUrls, resultChan chan<- types.IssuerCrlPaths, progBar *mpb.Bar) {
	defer wg.Done()

	for tuple := range crlsChan {
		paths := make([]string, 0)

		for _, crlUrl := range tuple.Urls {
			select {
			case <-ctx.Done():
				return
			default:
			}

			path, err := ae.crlFetchWorkerProcessOne(ctx, crlUrl, tuple.Issuer)
			if err != nil {
				glog.Warningf("[%s] CRL %s path=%s had error=%s", tuple.Issuer.ID(), crlUrl.String(), path, err)
			}
			if path != "" {
				paths = append(paths, path)
			}
		}

		subj, err := ae.issuers.GetSubjectForIssuer(tuple.Issuer)
		if err != nil {
			glog.Error(err)
		}

		resultChan <- types.IssuerCrlPaths{
			Issuer:   tuple.Issuer,
			IssuerDN: subj,
			CrlPaths: paths,
		}

		progBar.Increment()
	}
}

func loadAndCheckSignatureOfCRL(aPath string, aIssuerCert *x509.Certificate) (*pkix.CertificateList, error) {
	crlBytes, err := ioutil.ReadFile(aPath)
	if err != nil {
		return nil, fmt.Errorf("Error reading CRL, will not process revocations: %s", err)
	}

	crl, err := x509.ParseCRL(crlBytes)
	if err != nil {
		return nil, fmt.Errorf("Error parsing, will not process revocations: %s", err)
	}

	if err = aIssuerCert.CheckCRLSignature(crl); err != nil {
		return nil, fmt.Errorf("Invalid signature on CRL, will not process revocations: %s", err)
	}

	return crl, err
}

func verifyCRL(aPath string, aIssuerCert *x509.Certificate, aPreviousPath string) (*pkix.CertificateList, error) {
	glog.V(1).Infof("[%s] Verifying CRL", aPath)

	crl, err := loadAndCheckSignatureOfCRL(aPath, aIssuerCert)
	if err != nil {
		return nil, err
	}

	if _, err = os.Stat(aPreviousPath); err == nil {
		previousCrl, err := loadAndCheckSignatureOfCRL(aPreviousPath, aIssuerCert)
		if err != nil {
			return nil, err
		}

		if previousCrl.TBSCertList.ThisUpdate.After(crl.TBSCertList.ThisUpdate) {
			return previousCrl, fmt.Errorf("[%s] CRL is older than the previous CRL (previous=%s, this=%s)",
				aPath, previousCrl.TBSCertList.ThisUpdate, crl.TBSCertList.ThisUpdate)
		}
	}

	if crl.HasExpired(time.Now()) {
		glog.Warningf("[%s] CRL is expired, but proceeding anyway. (ThisUpdate=%s,"+
			" NextUpdate=%s)", aPath, crl.TBSCertList.ThisUpdate, crl.TBSCertList.NextUpdate)
	}

	return crl, nil
}

func processCRL(aCRL *pkix.CertificateList) ([]storage.Serial, error) {
	revokedList, err := types.DecodeRawTBSCertList(aCRL.TBSCertList.Raw)
	if err != nil {
		return []storage.Serial{}, fmt.Errorf("CRL list couldn't be decoded: %s", err)
	}

	serials := make([]storage.Serial, 0, 1024*16)
	for _, ent := range revokedList.RevokedCertificates {
		serial := storage.NewSerialFromBytes(ent.SerialNumber.Bytes)
		serials = append(serials, serial)
	}

	return serials, nil
}

func (ae *AggregateEngine) aggregateCRLWorker(ctx context.Context, wg *sync.WaitGroup,
	workChan <-chan types.IssuerCrlPaths, progBar *mpb.Bar) {
	defer wg.Done()

	for tuple := range workChan {
		issuerEnrolled := false

		cert, err := ae.issuers.GetCertificateForIssuer(tuple.Issuer)
		if err != nil {
			glog.Fatalf("[%s] Could not find certificate for issuer: %s", tuple.Issuer.ID(), err)
		}

		serialCount := 0
		serials := make([]storage.Serial, 0, 128*1024)

		for _, crlPath := range tuple.CrlPaths {
			select {
			case <-ctx.Done():
				return
			default:
				crl, err := verifyCRL(crlPath, cert, "")
				if err != nil {
					glog.Errorf("[%s] Failed to verify: %s", crlPath, err)
					continue
				}

				revokedSerials, err := processCRL(crl)
				if err != nil {
					glog.Errorf("[%s] Failed to process: %s", crlPath, err)
					continue
				}

				revokedCount := len(revokedSerials)
				if revokedCount == 0 {
					continue
				}

				// Issuer is considered enrolled if at least one CRL processed successfully
				if !issuerEnrolled {
					issuerEnrolled = true
					ae.issuers.Enroll(tuple.Issuer)
				}

				serials = append(serials, revokedSerials...)
				serialCount += revokedCount
			}
		}

		if issuerEnrolled {
			glog.Infof("[%s] Saving %d revoked serials", tuple.Issuer.ID(), serialCount)
			if err := ae.saveStorage.StoreKnownCertificateList(ctx, tuple.Issuer, serials); err != nil {
				glog.Fatalf("[%s] Could not save revoked certificates file: %s", tuple.Issuer.ID(), err)
			}

			glog.Infof("[%s] %d total revoked serials for %s (len=%d, cap=%d)", tuple.Issuer.ID(),
				serialCount, tuple.IssuerDN, len(serials), cap(serials))
		} else {
			glog.Infof("Issuer %s not enrolled", tuple.Issuer.ID())
		}

		progBar.Increment()
	}
}

func (ae *AggregateEngine) identifyCrlsByIssuer(ctx context.Context) types.IssuerCrlMap {
	var wg sync.WaitGroup

	glog.Infof("Listing issuers and their expiration dates...")
	issuerList, err := ae.loadStorageDB.GetIssuerAndDatesFromCache()
	if err != nil {
		glog.Fatal(err)
	}

	issuerChan := make(chan storage.Issuer, len(issuerList))

	var count int64
	for _, issuerObj := range issuerList {
		if !ae.issuers.IsIssuerInProgram(issuerObj.Issuer) {
			continue
		}

		select {
		case <-ctx.Done():
			glog.Infof("Quit received")
			break
		case issuerChan <- issuerObj.Issuer:
			count = count + 1
		default:
			glog.Fatalf("Channel overflow. Aborting at %s", issuerObj.Issuer.ID())
		}
	}

	// Signal that was the last work
	close(issuerChan)

	progressBar := ae.display.AddBar(count,
		mpb.PrependDecorators(
			decor.Name("Identify CRLs"),
		),
		mpb.AppendDecorators(
			decor.Percentage(),
			decor.Name(""),
			decor.AverageETA(decor.ET_STYLE_GO, decor.WC{W: 14}),
			decor.CountersNoUnit("%d / %d", decor.WCSyncSpace),
		),
		mpb.BarRemoveOnComplete(),
	)

	resultChan := make(chan types.IssuerCrlMap, *ctconfig.NumThreads)

	// Start the workers
	for t := 0; t < *ctconfig.NumThreads; t++ {
		wg.Add(1)
		go ae.findCrlWorker(ctx, &wg, issuerChan, resultChan, progressBar)
	}

	// Set up a notifier for the workers closing
	doneChan := make(chan bool)
	go func(wait *sync.WaitGroup) {
		wait.Wait()
		doneChan <- true
	}(&wg)

	select {
	case <-ctx.Done():
		glog.Infof("Signal caught, stopping threads at next opportunity.")
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

func (ae *AggregateEngine) downloadCRLs(ctx context.Context, issuerToUrls types.IssuerCrlMap) (<-chan types.IssuerCrlPaths, int64) {
	var wg sync.WaitGroup

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
			decor.AverageETA(decor.ET_STYLE_GO, decor.WC{W: 14}),
			decor.CountersNoUnit("%d / %d", decor.WCSyncSpace),
		),
		mpb.BarRemoveOnComplete(),
	)

	resultChan := make(chan types.IssuerCrlPaths, count)

	// Start the workers
	for t := 0; t < *ctconfig.NumThreads; t++ {
		wg.Add(1)
		go ae.crlFetchWorker(ctx, &wg, crlChan, resultChan, progressBar)
	}

	// Set up a notifier for the workers closing
	doneChan := make(chan bool)
	go func(wait *sync.WaitGroup) {
		wait.Wait()
		doneChan <- true
	}(&wg)

	select {
	case <-doneChan:
		progressBar.SetTotal(progressBar.Current(), true)
		close(resultChan)
		return resultChan, count
	}
}

func (ae *AggregateEngine) aggregateCRLs(ctx context.Context, count int64, crlPaths <-chan types.IssuerCrlPaths) {
	var wg sync.WaitGroup

	progressBar := ae.display.AddBar(count,
		mpb.PrependDecorators(
			decor.Name("Aggregate CRLs"),
		),
		mpb.AppendDecorators(
			decor.Percentage(),
			decor.Name(""),
			decor.AverageETA(decor.ET_STYLE_GO, decor.WC{W: 14}),
			decor.CountersNoUnit("%d / %d", decor.WCSyncSpace),
		),
		mpb.BarRemoveOnComplete(),
	)

	// Start the workers
	for t := 0; t < *ctconfig.NumThreads; t++ {
		wg.Add(1)
		go ae.aggregateCRLWorker(ctx, &wg, crlPaths, progressBar)
	}

	// Set up a notifier for the workers closing
	doneChan := make(chan bool)
	go func(wait *sync.WaitGroup) {
		wait.Wait()
		doneChan <- true
	}(&wg)

	select {
	case <-doneChan:
		progressBar.SetTotal(progressBar.Current(), true)
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
	ctx, cancel := context.WithCancel(context.Background())
	storageDB, remoteCache, _ := engine.GetConfiguredStorage(ctx, ctconfig)
	defer glog.Flush()

	checkPathArg(*revokedpath, "revokedpath", ctconfig)
	checkPathArg(*crlpath, "crlpath", ctconfig)
	checkPathArg(*enrolledpath, "enrolledpath", ctconfig)

	if err := os.MkdirAll(*revokedpath, permModeDir); err != nil {
		glog.Fatalf("Unable to make the revokedpath directory: %s", err)
	}
	if err := os.MkdirAll(*crlpath, permModeDir); err != nil {
		glog.Fatalf("Unable to make the CRL directory: %s", err)
	}

	refreshDur, err := time.ParseDuration(*ctconfig.OutputRefreshPeriod)
	if err != nil {
		glog.Fatal(err)
	}
	glog.Infof("Progress bar refresh rate is every %s.\n", refreshDur.String())

	engine.PrepareTelemetry("aggregate-crls", ctconfig)

	saveBackend := storage.NewLocalDiskBackend(permMode, *revokedpath)

	mozIssuers := rootprogram.NewMozillaIssuers()
	if *inccadb != "<path>" {
		err = mozIssuers.LoadFromDisk(*inccadb)
	} else {
		err = mozIssuers.Load()
	}

	if err != nil {
		glog.Fatalf("Unable to load the Mozilla issuers: %s", err)
	}

	// Exit signal, used by signals from the OS
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, os.Interrupt)
	defer signal.Stop(sigChan)

	go func() {
		<-sigChan
		glog.Infof("Signal caught, stopping threads at next opportunity.")
		cancel()
		signal.Stop(sigChan)
	}()

	var barOutput io.Writer = nil
	if nobars != nil && !*nobars {
		barOutput = os.Stdout
	}

	display := mpb.NewWithContext(ctx,
		mpb.WithRefreshRate(refreshDur),
		mpb.WithOutput(barOutput),
	)

	ae := AggregateEngine{
		loadStorageDB: storageDB,
		saveStorage:   saveBackend,
		remoteCache:   remoteCache,
		issuers:       mozIssuers,
		display:       display,
	}

	mergedCrls := ae.identifyCrlsByIssuer(ctx)
	if mergedCrls == nil {
		return
	}

	crlPaths, count := ae.downloadCRLs(ctx, mergedCrls)

	if ctx.Err() != nil {
		return
	}

	ae.aggregateCRLs(ctx, count, crlPaths)
	if err = mozIssuers.SaveIssuersList(*enrolledpath); err != nil {
		glog.Fatalf("Unable to save the crlite-informed intermediate issuers to %s: %s", *enrolledpath, err)
	}
	glog.Infof("Saved crlite-informed intermediate issuers to %s", *enrolledpath)
}
