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

	"github.com/armon/go-metrics"
	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"
	"github.com/mozilla/crlite/go"
	"github.com/mozilla/crlite/go/config"
	"github.com/mozilla/crlite/go/downloader"
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
	inccadb      = flag.String("ccadb", "<path>", "input CCADB CSV path")
	crlpath      = flag.String("crlpath", "<path>", "root of folders of the form /<path>/<issuer> containing .crl files to be updated")
	revokedpath  = flag.String("revokedpath", "<path>", "output folder of revoked serial files of the form <issuer>")
	enrolledpath = flag.String("enrolledpath", "<path>", "output JSON file of issuers with their enrollment status")
	auditpath    = flag.String("auditpath", "<path>", "output JSON audit report")
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
	auditor *CrlAuditor
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

type CrlVerifier struct {
	expectedIssuerCert *x509.Certificate
}

func (cv *CrlVerifier) IsValid(path string) error {
	_, _, err := loadAndCheckSignatureOfCRL(path, cv.expectedIssuerCert)
	return err
}

func (ae *AggregateEngine) crlFetchWorkerProcessOne(ctx context.Context, crlUrl url.URL, issuer storage.Issuer) (string, error) {
	err := os.MkdirAll(filepath.Join(*crlpath, issuer.ID()), permModeDir)
	if err != nil {
		glog.Warningf("Couldn't make directory: %s", err)
		return "", err
	}

	filename := makeFilenameFromUrl(crlUrl)
	finalPath := filepath.Join(*crlpath, issuer.ID(), filename)

	cert, err := ae.issuers.GetCertificateForIssuer(issuer)
	if err != nil {
		glog.Fatalf("[%s] Could not find certificate for issuer: %s", issuer.ID(), err)
	}

	verifyFunc := &CrlVerifier{
		expectedIssuerCert: cert,
	}

	fileOnDiskIsAcceptable, dlErr := downloader.DownloadAndVerifyFileSync(ctx, verifyFunc, ae.auditor,
		&issuer, ae.display, crlUrl, finalPath, 3, 300*time.Second)
	if !fileOnDiskIsAcceptable {
		glog.Errorf("[%s] Could not download, and no local file, will not be populating the "+
			"revocations: %s", crlUrl.String(), dlErr)
		return "", dlErr
	}
	if dlErr != nil {
		glog.Errorf("[%s] Problem downloading: %s", crlUrl.String(), dlErr)
	}

	// Ensure the final path is acceptable
	localSize, localDate, err := downloader.GetSizeAndDateOfFile(finalPath)
	if err != nil {
		glog.Errorf("[%s] Unexpected error on local file, will not be populating the "+
			"revocations: %s", crlUrl.String(), err)
		return "", err
	}

	age := time.Now().Sub(localDate)

	if age > allowableAgeOfLocalCRL {
		ae.auditor.Old(&issuer, &crlUrl, age)
		glog.Warningf("[%s] CRL appears not very fresh, but proceeding with expiration check. Age: %s", crlUrl.String(), age)
	}

	glog.Infof("[%s] Updated CRL %s (path=%s) (sz=%d) (age=%s)", issuer.ID(), crlUrl.String(),
		finalPath, localSize, age)

	return finalPath, nil
}

func (ae *AggregateEngine) crlFetchWorker(ctx context.Context, wg *sync.WaitGroup,
	crlsChan <-chan types.IssuerCrlUrls, resultChan chan<- types.IssuerCrlUrlPaths, progBar *mpb.Bar) {
	defer wg.Done()

	for tuple := range crlsChan {
		urlPaths := make([]types.UrlPath, 0)

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
			// Even if err is set, pass the blank path to the results, so we
			// can use it in enrolled/not enrolled determination
			urlPaths = append(urlPaths, types.UrlPath{Path: path, Url: crlUrl})
		}

		subj, err := ae.issuers.GetSubjectForIssuer(tuple.Issuer)
		if err != nil {
			glog.Error(err)
		}

		resultChan <- types.IssuerCrlUrlPaths{
			Issuer:      tuple.Issuer,
			IssuerDN:    subj,
			CrlUrlPaths: urlPaths,
		}

		progBar.Increment()
	}
}

func loadAndCheckSignatureOfCRL(aPath string, aIssuerCert *x509.Certificate) (*pkix.CertificateList, []byte, error) {
	crlBytes, err := ioutil.ReadFile(aPath)
	if err != nil {
		return nil, []byte{}, fmt.Errorf("Error reading CRL, will not process revocations: %s", err)
	}

	crl, err := x509.ParseCRL(crlBytes)
	if err != nil {
		return nil, []byte{}, fmt.Errorf("Error parsing, will not process revocations: %s", err)
	}

	if err = aIssuerCert.CheckCRLSignature(crl); err != nil {
		return nil, []byte{}, fmt.Errorf("Invalid signature on CRL, will not process revocations: %s", err)
	}

	shasum := sha256.Sum256(crlBytes)
	return crl, shasum[:], err
}

func (ae *AggregateEngine) verifyCRL(aIssuer storage.Issuer, dlTracer *downloader.DownloadTracer, crlUrl *url.URL, aPath string, aIssuerCert *x509.Certificate, aPreviousPath string) (*pkix.CertificateList, error) {
	glog.V(1).Infof("[%s] Verifying CRL from URL %s", aPath, crlUrl)

	crl, _, err := loadAndCheckSignatureOfCRL(aPath, aIssuerCert)
	if err != nil {
		ae.auditor.FailedVerifyUrl(&aIssuer, crlUrl, dlTracer, err)
		return nil, err
	}

	if _, err = os.Stat(aPreviousPath); err == nil {
		previousCrl, _, err := loadAndCheckSignatureOfCRL(aPreviousPath, aIssuerCert)
		if err != nil {
			ae.auditor.FailedVerifyPath(&aIssuer, crlUrl, aPreviousPath, err)
			return nil, err
		}

		if previousCrl.TBSCertList.ThisUpdate.After(crl.TBSCertList.ThisUpdate) {
			ae.auditor.FailedOlderThanPrevious(&aIssuer, crlUrl, dlTracer, previousCrl.TBSCertList.ThisUpdate, crl.TBSCertList.ThisUpdate)
			return previousCrl, fmt.Errorf("[%s] CRL is older than the previous CRL (previous=%s, this=%s)",
				aPath, previousCrl.TBSCertList.ThisUpdate, crl.TBSCertList.ThisUpdate)
		}
	}

	if crl.HasExpired(time.Now()) {
		ae.auditor.Expired(&aIssuer, crlUrl, crl.TBSCertList.NextUpdate)
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
	workChan <-chan types.IssuerCrlUrlPaths, progBar *mpb.Bar) {
	defer wg.Done()

	for tuple := range workChan {
		anyCrlFailed := false

		cert, err := ae.issuers.GetCertificateForIssuer(tuple.Issuer)
		if err != nil {
			glog.Fatalf("[%s] Could not find certificate for issuer: %s", tuple.Issuer.ID(), err)
		}

		serialCount := 0
		serials := make([]storage.Serial, 0, 128*1024)

		for _, crlUrlPath := range tuple.CrlUrlPaths {
			select {
			case <-ctx.Done():
				return
			default:
				if crlUrlPath.Path == "" {
					anyCrlFailed = true
					// DownloadAndVerifyFileSync already notified the auditor
					glog.Errorf("[%+v] Failed to download: %s", crlUrlPath, err)
					continue
				}

				crl, sha256sum, err := loadAndCheckSignatureOfCRL(crlUrlPath.Path, cert)
				if err != nil {
					anyCrlFailed = true
					ae.auditor.FailedVerifyPath(&tuple.Issuer, &crlUrlPath.Url, crlUrlPath.Path, err)
					glog.Errorf("[%+v] Failed to verify: %s", crlUrlPath, err)
					continue
				}

				revokedSerials, err := processCRL(crl)
				if err != nil {
					anyCrlFailed = true
					ae.auditor.FailedProcessLocal(&tuple.Issuer, &crlUrlPath.Url, crlUrlPath.Path, err)
					glog.Errorf("[%+v] Failed to process: %s", crlUrlPath, err)
					continue
				}

				revokedCount := len(revokedSerials)
				if revokedCount == 0 {
					ae.auditor.NoRevocations(&tuple.Issuer, &crlUrlPath.Url, crlUrlPath.Path)
					continue
				}

				age := time.Since(crl.TBSCertList.ThisUpdate)

				ae.auditor.ValidAndProcessed(&tuple.Issuer, &crlUrlPath.Url, crlUrlPath.Path, revokedCount, age, sha256sum)
				serials = append(serials, revokedSerials...)
				serialCount += revokedCount
			}
		}

		// Issuer is considered enrolled if no CRLs failed to download or process,
		// and at least one revocation was collected
		if anyCrlFailed == false && serialCount > 0 {
			ae.issuers.Enroll(tuple.Issuer)

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

func (ae *AggregateEngine) downloadCRLs(ctx context.Context, issuerToUrls types.IssuerCrlMap) (<-chan types.IssuerCrlUrlPaths, int64) {
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

	resultChan := make(chan types.IssuerCrlUrlPaths, count)

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

func (ae *AggregateEngine) aggregateCRLs(ctx context.Context, count int64, crlPaths <-chan types.IssuerCrlUrlPaths) {
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
	storageDB, remoteCache := engine.GetConfiguredStorage(ctx, ctconfig)
	defer glog.Flush()

	checkPathArg(*revokedpath, "revokedpath", ctconfig)
	checkPathArg(*crlpath, "crlpath", ctconfig)
	checkPathArg(*enrolledpath, "enrolledpath", ctconfig)
	checkPathArg(*auditpath, "auditpath", ctconfig)

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
		mozIssuers.DiskPath = *inccadb
	}

	err = mozIssuers.Load()
	if err != nil {
		glog.Fatalf("Unable to load the Mozilla issuers: %s", err)
		return
	}

	metrics.SetGauge([]string{"IssuersAgeSeconds"}, float32(mozIssuers.DatasetAge().Seconds()))

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

	auditor := NewCrlAuditor(mozIssuers)

	ae := AggregateEngine{
		loadStorageDB: storageDB,
		saveStorage:   saveBackend,
		remoteCache:   remoteCache,
		issuers:       mozIssuers,
		display:       display,
		auditor:       auditor,
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

	fd, err := os.Create(*auditpath)
	if err != nil {
		glog.Warningf("Could not open audit report path %s: %v", *auditpath, err)
		return
	}
	if err = auditor.WriteReport(fd); err != nil {
		glog.Warningf("Could not write audit report %s: %v", *auditpath, err)
	}
	err = fd.Close()
	if err != nil {
		glog.Warningf("Could not close audit report %s: %v", *auditpath, err)
	}
}
