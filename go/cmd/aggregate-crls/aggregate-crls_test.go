package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"
	"github.com/mozilla/crlite/go"
	"github.com/mozilla/crlite/go/downloader"
	"github.com/mozilla/crlite/go/rootprogram"
	"github.com/mozilla/crlite/go/storage"
	"github.com/vbauerster/mpb/v5"
)

func Test_makeFilenameFromUrl(t *testing.T) {
	names := make(map[string]bool)

	checkCollision := func(t *testing.T, list []string, db map[string]bool) {
		for _, crl := range list {
			url, _ := url.Parse(crl)

			filename := makeFilenameFromUrl(*url)
			if db[filename] {
				t.Errorf("Name collision: %s in %v", filename, db)
			}

			db[filename] = true
		}
	}

	crls := []string{"http://repository.net/crl/1000-1/complete.crl",
		"http://repository.net/crl/100-1/complete.crl",
		"http://repository.net/crl/10-1/complete.crl",
		"http://repository.net/crl/complete.crl"}
	checkCollision(t, crls, names)

	crls2 := []string{"http://repository.com/crl",
		"http://repository.com/crl.crl",
		"http://crl.repository.com/",
		"http://crl.repository.com/crl"}
	checkCollision(t, crls2, names)
}

func makeCA(t *testing.T) (*x509.Certificate, interface{}) {
	t.Helper()
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			CommonName: "Honest Achmed's Used Certificates and CRLs",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		t.Fatal(err)
	}

	ca, err := x509.ParseCertificate(caBytes)
	if err != nil {
		t.Fatal(err)
	}

	return ca, caPrivKey
}

func makeCRL(t *testing.T, ca *x509.Certificate, caPrivKey interface{}, thisUpdate time.Time, nextUpdate time.Time) []byte {
	t.Helper()
	revokedCerts := []pkix.RevokedCertificate{}

	crlBytes, err := ca.CreateCRL(rand.Reader, caPrivKey, revokedCerts, thisUpdate, nextUpdate)
	if err != nil {
		t.Fatal(err)
	}

	return crlBytes
}

func Test_loadAndCheckSignatureOfCRL(t *testing.T) {
	thisUpdate := time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)
	nextUpdate := time.Date(2020, time.February, 1, 0, 0, 0, 0, time.UTC)

	ca, caPrivKey := makeCA(t)

	crlBytes := makeCRL(t, ca, caPrivKey, thisUpdate, nextUpdate)

	crlPath, err := ioutil.TempFile("", "loadAndCheckSignatureOfCRL")
	if err != nil {
		t.Fatal(err)
	}

	defer os.Remove(crlPath.Name())

	if _, err := crlPath.Write(crlBytes); err != nil {
		t.Fatal(err)
	}
	if err := crlPath.Close(); err != nil {
		t.Fatal(err)
	}

	list, sha256sum, err := loadAndCheckSignatureOfCRL(crlPath.Name(), ca)
	if err != nil {
		t.Error(err)
	}

	if list.TBSCertList.ThisUpdate != thisUpdate {
		t.Error("This Update didn't match")
	}

	if list.TBSCertList.NextUpdate != nextUpdate {
		t.Error("This Update didn't match")
	}

	if len(sha256sum) != 32 {
		t.Error("Expected a 32-byte sha256 digest")
	}

	otherCa, _ := makeCA(t)
	_, _, err = loadAndCheckSignatureOfCRL(crlPath.Name(), otherCa)
	if !strings.Contains(err.Error(), "verification failure") {
		t.Error(err)
	}
}

func Test_verifyCRL(t *testing.T) {
	issuersObj := rootprogram.NewMozillaIssuers()
	dlTracer := downloader.NewDownloadTracer()
	auditor := NewCrlAuditor(issuersObj)
	issuer := issuersObj.NewTestIssuerFromSubjectString("Test Corporation SA")
	url, _ := url.Parse("http://test/crl")
	storageDB, _ := storage.NewCertDatabase(storage.NewMockRemoteCache())
	display := mpb.New(
		mpb.WithOutput(ioutil.Discard),
	)

	ae := AggregateEngine{
		loadStorageDB: storageDB,
		saveStorage:   storage.NewMockBackend(),
		remoteCache:   storage.NewMockRemoteCache(),
		issuers:       issuersObj,
		display:       display,
		auditor:       auditor,
	}

	todayThisUpdate := time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)
	todayNextUpdate := time.Date(2020, time.February, 1, 0, 0, 0, 0, time.UTC)

	ca, caPrivKey := makeCA(t)

	todayCrlBytes := makeCRL(t, ca, caPrivKey, todayThisUpdate, todayNextUpdate)
	todayCrlPath, err := ioutil.TempFile("", "todays_crl")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(todayCrlPath.Name())
	if _, err := todayCrlPath.Write(todayCrlBytes); err != nil {
		t.Fatal(err)
	}
	if err := todayCrlPath.Close(); err != nil {
		t.Fatal(err)
	}

	// Prompt the case where yesterday's was newer than today's
	yesterdayThisUpdate := time.Date(2020, time.January, 2, 0, 0, 0, 0, time.UTC)
	yesterdayNextUpdate := time.Date(2020, time.February, 2, 0, 0, 0, 0, time.UTC)

	yesterdayCrlBytes := makeCRL(t, ca, caPrivKey, yesterdayThisUpdate, yesterdayNextUpdate)
	yesterdayCrlPath, err := ioutil.TempFile("", "yesterdays_crl")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(yesterdayCrlPath.Name())
	if _, err := yesterdayCrlPath.Write(yesterdayCrlBytes); err != nil {
		t.Fatal(err)
	}
	if err := yesterdayCrlPath.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = ae.verifyCRL(issuer, dlTracer, url, todayCrlPath.Name(), ca, yesterdayCrlPath.Name())
	if !strings.Contains(err.Error(), "CRL is older than the previous CRL") {
		t.Error(err)
	}

	// Should work fine this orientation
	list, err := ae.verifyCRL(issuer, dlTracer, url, yesterdayCrlPath.Name(), ca, todayCrlPath.Name())
	if err != nil {
		t.Error(err)
	}
	if list.TBSCertList.ThisUpdate != yesterdayThisUpdate {
		t.Error("This Update didn't match")
	}

	if list.TBSCertList.NextUpdate != yesterdayNextUpdate {
		t.Error("This Update didn't match")
	}

	_, otherCaPrivKey := makeCA(t)

	// Prompt the case where yesterday's is OK but today's is mis-signed
	todayOtherSignerCrlBytes := makeCRL(t, ca, otherCaPrivKey, todayThisUpdate, todayNextUpdate)
	todayOtherSignerCrlPath, err := ioutil.TempFile("", "todays_other_signer_crl")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(todayOtherSignerCrlPath.Name())
	if _, err := todayOtherSignerCrlPath.Write(todayOtherSignerCrlBytes); err != nil {
		t.Fatal(err)
	}
	if err := todayOtherSignerCrlPath.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = ae.verifyCRL(issuer, dlTracer, url, todayOtherSignerCrlPath.Name(), ca, yesterdayCrlPath.Name())
	if !strings.Contains(err.Error(), "verification failure") {
		t.Error(err)
	}
}

func hostCRL(t *testing.T, crlBytes []byte) *httptest.Server {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write(crlBytes)
		if err != nil {
			t.Error(err)
		}
	})

	return httptest.NewServer(handler)
}

func Test_crlFetchWorker(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "Test_crlFetchWorker")
	if err != nil {
		t.Error(err)
	}
	*crlpath = tmpDir
	defer os.RemoveAll(tmpDir)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup

	display := mpb.New(
		mpb.WithOutput(ioutil.Discard),
	)

	storageDB, _ := storage.NewCertDatabase(storage.NewMockRemoteCache())
	issuersObj := rootprogram.NewMozillaIssuers()
	auditor := NewCrlAuditor(issuersObj)

	ae := AggregateEngine{
		loadStorageDB: storageDB,
		saveStorage:   storage.NewMockBackend(),
		remoteCache:   storage.NewMockRemoteCache(),
		issuers:       issuersObj,
		display:       display,
		auditor:       auditor,
	}
	bar := display.AddBar(1)

	urlChan := make(chan types.IssuerCrlUrls, 16)
	resultChan := make(chan types.IssuerCrlUrlPaths, 16)

	ca, caPrivKey := makeCA(t)
	issuer := issuersObj.InsertIssuerFromCertAndPem(ca, "")

	thisUpdate := time.Now().UTC()
	nextUpdate := thisUpdate.AddDate(0, 0, 1)

	crlBytes := makeCRL(t, ca, caPrivKey, thisUpdate, nextUpdate)
	server := hostCRL(t, crlBytes)
	defer server.Close()

	wg.Add(1)
	go ae.crlFetchWorker(ctx, &wg, urlChan, resultChan, bar)

	unavailableUrl, _ := url.Parse("http://localhost:1/file")
	crl1Url, _ := url.Parse(server.URL + "/crl-1.crl")
	crl2Url, _ := url.Parse(server.URL + "/crl-2.crl")

	urlChan <- types.IssuerCrlUrls{
		Issuer: issuer,
		Urls:   []url.URL{},
	}

	urlChan <- types.IssuerCrlUrls{
		Issuer: issuer,
		Urls:   []url.URL{*unavailableUrl},
	}

	urlChan <- types.IssuerCrlUrls{
		Issuer: issuer,
		Urls:   []url.URL{*unavailableUrl, *crl1Url},
	}

	urlChan <- types.IssuerCrlUrls{
		Issuer: issuer,
		Urls:   []url.URL{*unavailableUrl, *crl1Url, *crl2Url},
	}

	close(urlChan)

	result := <-resultChan
	if result.Issuer.ID() != issuer.ID() {
		t.Error("Unexpected issuer")
	}
	if len(result.CrlUrlPaths) != 0 {
		t.Errorf("Unexpected CRLs: %+v", result.CrlUrlPaths)
	}

	result = <-resultChan
	if result.Issuer.ID() != issuer.ID() {
		t.Error("Unexpected issuer")
	}
	if len(result.CrlUrlPaths) != 1 {
		t.Errorf("Unexpected CRLs: %+v", result.CrlUrlPaths)
	}

	result = <-resultChan
	if result.Issuer.ID() != issuer.ID() {
		t.Error("Unexpected issuer")
	}
	if len(result.CrlUrlPaths) != 2 {
		t.Errorf("Unexpected CRLs: %+v", result.CrlUrlPaths)
	}

	result = <-resultChan
	if result.Issuer.ID() != issuer.ID() {
		t.Error("Unexpected issuer")
	}
	if len(result.CrlUrlPaths) != 3 {
		t.Errorf("Unexpected CRLs: %+v", result.CrlUrlPaths)
	}

	select {
	case msg := <-resultChan:
		t.Errorf("Unexpected message: %+v", msg)
	default:
	}

	assertAuditorReportHasEntries(t, auditor, 3)
	for _, e := range auditor.GetEntries() {
		assertEntryUrlAndIssuer(t, &e, issuer, issuersObj, unavailableUrl)
	}
}

func Test_crlFetchWorkerProcessOne(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "Test_crlFetchWorkerProcessOne")
	if err != nil {
		t.Error(err)
	}
	*crlpath = tmpDir
	defer os.RemoveAll(tmpDir)

	display := mpb.New(
		mpb.WithOutput(ioutil.Discard),
	)

	storageDB, _ := storage.NewCertDatabase(storage.NewMockRemoteCache())
	issuersObj := rootprogram.NewMozillaIssuers()
	auditor := NewCrlAuditor(issuersObj)

	ae := AggregateEngine{
		loadStorageDB: storageDB,
		saveStorage:   storage.NewMockBackend(),
		remoteCache:   storage.NewMockRemoteCache(),
		issuers:       issuersObj,
		display:       display,
		auditor:       auditor,
	}

	ca, caPrivKey := makeCA(t)
	issuer := issuersObj.InsertIssuerFromCertAndPem(ca, "")

	unavailableUrl, _ := url.Parse("http://localhost:1/file")

	path, err := ae.crlFetchWorkerProcessOne(context.TODO(), *unavailableUrl, issuer)
	if err == nil || !strings.Contains(err.Error(), "connect: connection refused") {
		t.Errorf("expected connect: connection refused error, got %v", err)
	}
	if path != "" {
		t.Errorf("Should not have gotten a path for the unavailable URL: %s", path)
	}

	thisUpdate := time.Now().UTC()
	nextUpdate := thisUpdate.AddDate(0, 0, 1)
	crlBytes := makeCRL(t, ca, caPrivKey, thisUpdate, nextUpdate)

	server := hostCRL(t, crlBytes)
	defer server.Close()

	availableUrl, _ := url.Parse(server.URL + "/crl")
	path, err = ae.crlFetchWorkerProcessOne(context.TODO(), *availableUrl, issuer)
	if err != nil {
		t.Error(err)
	}
	if !strings.Contains(path, "127.0.0.1-crl") {
		t.Errorf("Path on disk should be for this host: %s", path)
	}

	readBytes, err := ioutil.ReadFile(path)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(readBytes, crlBytes) {
		t.Error("Bytes on disk didn't match what was served")
	}

	assertAuditorReportHasEntries(t, auditor, 1)
	for _, e := range auditor.GetEntries() {
		assertEntryUrlAndIssuer(t, &e, issuer, issuersObj, unavailableUrl)
	}
}
