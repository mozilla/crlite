package main

import (
	"context"
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
	"github.com/google/certificate-transparency-go/x509/pkix"
	"github.com/mozilla/crlite/go"
	"github.com/mozilla/crlite/go/config"
	"github.com/mozilla/crlite/go/downloader"
	"github.com/mozilla/crlite/go/engine"
	"github.com/mozilla/crlite/go/rootprogram"
	"github.com/mozilla/crlite/go/storage"
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
	ctconfig     = config.NewCTConfig()

	illegalPath = regexp.MustCompile(`[^[:alnum:]\~\-\./]`)

	allowableAgeOfLocalCRL, _ = time.ParseDuration("336h")
)

type AggregateEngine struct {
	saveStorage storage.StorageBackend

	issuers *rootprogram.MozIssuers
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

type CrlVerifier struct {
	expectedIssuerCert *x509.Certificate
}

func (cv *CrlVerifier) IsValid(path string) error {
	_, _, err := loadAndCheckSignatureOfCRL(path, cv.expectedIssuerCert)
	return err
}

func (ae *AggregateEngine) crlFetchWorkerProcessOne(ctx context.Context, crlUrl url.URL, issuer types.Issuer) (string, error) {
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
		&issuer, crlUrl, finalPath, 3, 300*time.Second)
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
	crlsChan <-chan types.IssuerCrlUrls, resultChan chan<- types.IssuerCrlUrlPaths) {
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

func (ae *AggregateEngine) verifyCRL(aIssuer types.Issuer, dlTracer *downloader.DownloadTracer, crlUrl *url.URL, aPath string, aIssuerCert *x509.Certificate, aPreviousPath string) (*pkix.CertificateList, error) {
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

func processCRL(aCRL *pkix.CertificateList) ([]types.SerialAndReason, error) {
	revokedList, err := types.DecodeRawTBSCertList(aCRL.TBSCertList.Raw)
	if err != nil {
		return []types.SerialAndReason{}, fmt.Errorf("CRL list couldn't be decoded: %s", err)
	}

	serials := make([]types.SerialAndReason, 0, 1024*16)
	for _, ent := range revokedList.RevokedCertificates {
		serial, err := ent.SerialAndReason()
		if err != nil {
			return []types.SerialAndReason{}, fmt.Errorf("CRL list couldn't be decoded: %s", err)
		}
		serials = append(serials, serial)
	}

	return serials, nil
}

func (ae *AggregateEngine) aggregateCRLWorker(ctx context.Context, wg *sync.WaitGroup,
	workChan <-chan types.IssuerCrlUrlPaths) {
	defer wg.Done()

	for tuple := range workChan {
		anyCrlFailed := false

		cert, err := ae.issuers.GetCertificateForIssuer(tuple.Issuer)
		if err != nil {
			glog.Fatalf("[%s] Could not find certificate for issuer: %s", tuple.Issuer.ID(), err)
		}

		serialCount := 0
		serials := make([]types.SerialAndReason, 0, 128*1024)

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

		// Issuer is considered enrolled if all known CRLs were processed
		if anyCrlFailed == false {
			ae.issuers.Enroll(tuple.Issuer)

			if err := ae.saveStorage.StoreRevokedCertificateList(ctx, tuple.Issuer, serials); err != nil {
				glog.Fatalf("[%s] Could not save revoked certificates file: %s", tuple.Issuer.ID(), err)
			}

			glog.Infof("[%s] %d total revoked serials for %s (len=%d, cap=%d)", tuple.Issuer.ID(),
				serialCount, tuple.IssuerDN, len(serials), cap(serials))
		} else {
			glog.Infof("Issuer %s not enrolled", tuple.Issuer.ID())
		}
	}
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
				Issuer: types.NewIssuerFromString(issuer),
				Urls:   urls,
			}
			count = count + 1
		}
	}
	close(crlChan)

	resultChan := make(chan types.IssuerCrlUrlPaths, count)

	// Start the workers
	for t := 0; t < *ctconfig.NumThreads; t++ {
		wg.Add(1)
		go ae.crlFetchWorker(ctx, &wg, crlChan, resultChan)
	}
	wg.Wait()
	close(resultChan)

	return resultChan, count
}

func (ae *AggregateEngine) aggregateCRLs(ctx context.Context, count int64, crlPaths <-chan types.IssuerCrlUrlPaths) {
	var wg sync.WaitGroup

	// Start the workers
	for t := 0; t < *ctconfig.NumThreads; t++ {
		wg.Add(1)
		go ae.aggregateCRLWorker(ctx, &wg, crlPaths)
	}

	wg.Wait()
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

	engine.PrepareTelemetry("aggregate-crls", ctconfig)

	saveBackend := storage.NewLocalDiskBackend(permMode, *revokedpath)

	mozIssuers := rootprogram.NewMozillaIssuers()
	if *inccadb != "<path>" {
		mozIssuers.DiskPath = *inccadb
	}

	err := mozIssuers.Load()
	if err != nil {
		glog.Fatalf("Unable to load the Mozilla issuers: %s", err)
		return
	}

	glog.Infof("Issuer file age: %s", mozIssuers.DatasetAge().Round(time.Second))

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

	auditor := NewCrlAuditor(mozIssuers)

	ae := AggregateEngine{
		saveStorage: saveBackend,
		issuers:     mozIssuers,
		auditor:     auditor,
	}

	issuerCrlMap := make(types.IssuerCrlMap)
	for issuer, crls := range mozIssuers.CrlMap {
		issuerCrlMap[issuer] = make(map[string]bool)
		for crl, _ := range crls {
			issuerCrlMap[issuer][crl] = true
		}
	}

	crlPaths, count := ae.downloadCRLs(ctx, issuerCrlMap)

	if ctx.Err() != nil {
		return
	}

	ae.aggregateCRLs(ctx, count, crlPaths)
	if err := mozIssuers.SaveIssuersList(*enrolledpath); err != nil {
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
