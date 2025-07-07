package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
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

	illegalPath = regexp.MustCompile(`[^[:alnum:]\~\-\.]`)

	allowableAgeOfLocalCRL, _ = time.ParseDuration("336h")
)

type AggregateEngine struct {
	rootPath string

	issuers *rootprogram.MozIssuers
	auditor *CrlAuditor
}

func makeFilenameFromUrl(crlUrl url.URL) string {
	filename := fmt.Sprintf("%s-%s", crlUrl.Hostname(), path.Base(crlUrl.Path))
	if len(crlUrl.RawQuery) > 0 {
		filename = fmt.Sprintf("%s-%s", filename, crlUrl.RawQuery)
	}
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
			// the path here might be blank if err is set
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

	if crl.HasExpired(time.Now()) {
		glog.Warningf("[%s] CRL is expired, but proceeding anyway. (ThisUpdate=%s,"+
			" NextUpdate=%s)", aPath, crl.TBSCertList.ThisUpdate, crl.TBSCertList.NextUpdate)
	}

	shasum := sha256.Sum256(crlBytes)
	return crl, shasum[:], err
}

func loadAndCheckIssuingDistributionPointOfCRL(aPath string, aFetchUrl string, aPartitionedCrlUrlSet map[string]bool) (bool, error) {
	// If a CA uses partitioned CRLs, then the fetch URL must appear as a fullName in the
	// issuingDistributionPoints extension. Moreover, it must be the only URL from the
	// collection of partitioned CRL URLs that appears in the issuingDistributionPoints
	// extension.
	//
	crlBytes, err := ioutil.ReadFile(aPath)
	if err != nil {
		return false, fmt.Errorf("Error reading CRL, will not process revocations: %s", err)
	}

	block, _ := pem.Decode(crlBytes)
	if block != nil {
		crlBytes = block.Bytes
	}

	// The certificate-transparency-go fork of x509 will parse the IssuingDP extension for us.
	// We don't use this parser in loadAndCheckSignatureOfCRL because it is more strict than the
	// standard x509 parser.
	crl, err := x509.ParseCertificateListDER(crlBytes)
	if err != nil {
		return false, fmt.Errorf("Error parsing, will not process revocations: %s", err)
	}

	urls := []string{}
	found := false
	for _, url := range crl.TBSCertList.IssuingDPFullNames.URIs {
		urls = append(urls, url)
		_, exists := aPartitionedCrlUrlSet[url]
		if exists {
			if aFetchUrl == url {
				found = true
			} else {
				return false, fmt.Errorf("The issuingDistributionPoints extension lists a different known CRL %s", url)
			}
		}
	}
	if found {
		return true, nil
	}
	return false, fmt.Errorf("Did not find matching URL in %v", urls)
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

		usesPartitionedCrls, err := ae.issuers.GetUsesPartitionedCrlsForIssuer(tuple.Issuer)
		if err != nil {
			glog.Warningf("[%s] Assuming that this issuer uses partitioned CRLs.", tuple.Issuer.ID())
			usesPartitionedCrls = true
		}

		partitionedCrlUrls := make(map[string]bool, len(tuple.CrlUrlPaths))
		if usesPartitionedCrls {
			for _, url := range tuple.CrlUrlPaths {
				partitionedCrlUrls[url.Url.String()] = true
			}
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

				if usesPartitionedCrls {
					// Per TLS BR Section 7.2.2.1 (version 2.1.5) and MRSP
					// Section 6.1.2 (version 3.0), each of its CRLs must
					// include an issuingDP extension with a fullName of URI
					// type that matches, byte-for-byte, a URL in the "JSON
					// Array of Partitioned CRLs" in CCADB.
					fetchUrl := crlUrlPath.Url.String()
					foundMatch, err := loadAndCheckIssuingDistributionPointOfCRL(crlUrlPath.Path, fetchUrl, partitionedCrlUrls)
					if err != nil || !foundMatch {
						ae.auditor.WrongIssuingDistributionPoint(&tuple.Issuer, &crlUrlPath.Url, crlUrlPath.Path, err)
						glog.Errorf("[%s] CRL shard at %s does not list that URL in its issuing DP extension", tuple.Issuer.ID(), fetchUrl)
					}
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

		if anyCrlFailed == false {
			if err := ae.StoreRevokedCertificateList(ctx, tuple.Issuer, serials); err != nil {
				glog.Fatalf("[%s] Could not save revoked certificates file: %s", tuple.Issuer.ID(), err)
			}

			glog.Infof("[%s] %d total revoked serials for %s (len=%d, cap=%d)", tuple.Issuer.ID(),
				serialCount, tuple.IssuerDN, len(serials), cap(serials))
		} else {
			glog.Infof("May not have all revoked certificates for issuer %s", tuple.Issuer.ID())
		}
	}
}

func (ae *AggregateEngine) downloadCRLs(ctx context.Context, mozIssuers *rootprogram.MozIssuers) (<-chan types.IssuerCrlUrlPaths, int64) {
	var wg sync.WaitGroup

	crlChan := make(chan types.IssuerCrlUrls, 16*1024*1024)
	var count int64
	for issuerStr, crlMap := range mozIssuers.CrlMap {
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
				Issuer: types.NewIssuerFromString(issuerStr),
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

// Write a line delimited list of serial numbers and reason codes to a text
// file. Each line contains hex encoded binary data. The first (encoded) byte
// in each line is the reason code. The remaining bytes are the serial number.
func (ae *AggregateEngine) StoreRevokedCertificateList(ctx context.Context, issuer types.Issuer,
	serials []types.SerialAndReason) error {

	// Ensure that the output directory exists
	err := os.MkdirAll(ae.rootPath, permModeDir)
	if err != nil {
		return err
	}

	path := filepath.Join(ae.rootPath, issuer.ID())

	fd, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, permMode)
	if err != nil {
		return err
	}
	defer fd.Close()

	writer := bufio.NewWriter(fd)
	defer writer.Flush()

	for _, s := range serials {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			_, err = writer.WriteString(hex.EncodeToString([]byte{s.Reason}))
			if err != nil {
				return err
			}
			_, err := writer.WriteString(s.Serial.HexString())
			if err != nil {
				return err
			}
			err = writer.WriteByte('\n')
			if err != nil {
				return err
			}
		}
	}
	return nil
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
		rootPath: *revokedpath,
		issuers:  mozIssuers,
		auditor:  auditor,
	}

	crlPaths, count := ae.downloadCRLs(ctx, mozIssuers)

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
