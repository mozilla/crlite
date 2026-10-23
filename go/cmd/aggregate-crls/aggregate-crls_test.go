package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdx509 "crypto/x509"
	stdpkix "crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"
	"github.com/mozilla/crlite/go"
	"github.com/mozilla/crlite/go/rootprogram"
)

func Test_makeFilenameFromUrl(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "Test_makeFilenameFromUrlTest")
	if err != nil {
		t.Error(err)
	}
	defer os.RemoveAll(tmpDir)

	checkOpenable := func(t *testing.T, tmpDir, crlUrl string) {
		url, _ := url.Parse(crlUrl)

		path := filepath.Join(tmpDir, makeFilenameFromUrl(*url))

		f, err := os.OpenFile(path, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			t.Errorf("Could not open file: %s", err)
		}
		f.Close()
	}

	for _, url := range []string{
		"http://example.com/",
		"http://example.com/?",
		"http://example.com/?abc",
		"http://example.com/crl/",
		"http://example.com/crl/?",
		"http://example.com/crl/?abc",
		"http://example.com/~crl/",
		"http://example.com/~crl/?",
		"http://example.com/~crl/?abc",
	} {
		checkOpenable(t, tmpDir, url)
	}
}

func Test_makeFilenameFromUrlCollisions(t *testing.T) {
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
			CommonName: "Only the Finest Certificates and CRLs",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte{1, 2, 3, 4},
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

func makeRevokedList(t *testing.T, r []pkix.RevokedCertificate) *types.TBSCertificateListWithRawSerials {
	ca, caPrivKey := makeCA(t)

	thisUpdate := time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)
	nextUpdate := time.Date(2020, time.February, 1, 0, 0, 0, 0, time.UTC)

	crlBytes, err := ca.CreateCRL(rand.Reader, caPrivKey, r, thisUpdate, nextUpdate)
	if err != nil {
		t.Fatal(err)
	}

	crl, err := x509.ParseCRL(crlBytes)
	if err != nil {
		t.Fatal(err)
	}

	revokedList, err := types.DecodeRawTBSCertList(crl.TBSCertList.Raw)
	if err != nil {
		t.Fatal(err)
	}

	return revokedList
}

func Test_keyCompromiseReasonCode(t *testing.T) {
	t.Helper()

	var keyCompromise []byte
	keyCompromise, err := asn1.Marshal(asn1.Enumerated(1))
	if err != nil {
		t.Fatal(err)
	}

	revokedList := makeRevokedList(t,
		[]pkix.RevokedCertificate{
			pkix.RevokedCertificate{
				SerialNumber:   big.NewInt(int64(123456789)),
				RevocationTime: time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC),
				Extensions: []pkix.Extension{
					pkix.Extension{
						Id:    []int{2, 5, 29, 21},
						Value: keyCompromise,
					},
				},
			},
		})

	received, err := revokedList.RevokedCertificates[0].Reason()
	if err != nil {
		t.Fatal(err)
	}

	if received != asn1.Enumerated(1) {
		t.Error("expected keyCompromise reason code")
	}
}

func Test_unspecifiedReasonCode(t *testing.T) {
	t.Helper()

	revokedList := makeRevokedList(t,
		[]pkix.RevokedCertificate{
			pkix.RevokedCertificate{
				SerialNumber:   big.NewInt(int64(123456789)),
				RevocationTime: time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC),
			}})

	received, err := revokedList.RevokedCertificates[0].Reason()
	if err != nil {
		t.Fatal(err)
	}

	if received != asn1.Enumerated(0) {
		t.Error("expected unspecified reason code")
	}
}

func Test_invalidReasonCode(t *testing.T) {
	t.Helper()

	var negativeReason []byte
	negativeReason, err := asn1.Marshal(asn1.Enumerated(-1))
	if err != nil {
		t.Fatal(err)
	}

	var largeReason []byte
	largeReason, err = asn1.Marshal(asn1.Enumerated(256))
	if err != nil {
		t.Fatal(err)
	}

	template := []pkix.RevokedCertificate{
		pkix.RevokedCertificate{
			SerialNumber:   big.NewInt(int64(123456789)),
			RevocationTime: time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC),
			Extensions: []pkix.Extension{
				pkix.Extension{
					Id: []int{2, 5, 29, 21},
				},
			},
		}}

	for _, reason := range [][]byte{negativeReason, largeReason} {
		template[0].Extensions[0].Value = reason
		revokedList := makeRevokedList(t, template)

		_, err = revokedList.RevokedCertificates[0].Reason()
		if err == nil {
			t.Fatal("expected error")
		}
	}
}

func Test_repeatedReasonCode(t *testing.T) {
	t.Helper()

	var keyCompromise []byte
	keyCompromise, err := asn1.Marshal(asn1.Enumerated(1))
	if err != nil {
		t.Fatal(err)
	}

	var certificateHold []byte
	certificateHold, err = asn1.Marshal(asn1.Enumerated(6))
	if err != nil {
		t.Fatal(err)
	}

	revokedList := makeRevokedList(t,
		[]pkix.RevokedCertificate{
			pkix.RevokedCertificate{
				SerialNumber:   big.NewInt(int64(123456789)),
				RevocationTime: time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC),
				Extensions: []pkix.Extension{
					pkix.Extension{
						Id:    []int{2, 5, 29, 21},
						Value: keyCompromise,
					},
					pkix.Extension{
						Id:    []int{0, 0, 0, 0},
						Value: []byte{},
					},
					pkix.Extension{
						Id:    []int{2, 5, 29, 21},
						Value: certificateHold,
					},
				},
			}})

	_, err = revokedList.RevokedCertificates[0].Reason()
	if err == nil {
		t.Fatal("expected error")
	}
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

	issuersObj := rootprogram.NewMozillaIssuers()
	auditor := NewCrlAuditor(issuersObj)

	ae := AggregateEngine{
		rootPath: tmpDir,
		issuers:  issuersObj,
		auditor:  auditor,
	}

	urlChan := make(chan types.IssuerCrlUrls, 16)
	resultChan := make(chan types.IssuerCrlUrlPaths, 16)

	ca, caPrivKey := makeCA(t)
	issuer := issuersObj.InsertIssuer(ca, nil, nil, false)

	thisUpdate := time.Now().UTC()
	nextUpdate := thisUpdate.AddDate(0, 0, 1)

	crlBytes := makeCRL(t, ca, caPrivKey, thisUpdate, nextUpdate)
	server := hostCRL(t, crlBytes)
	defer server.Close()

	wg.Add(1)
	go ae.crlFetchWorker(ctx, &wg, urlChan, resultChan)

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

	issuersObj := rootprogram.NewMozillaIssuers()
	auditor := NewCrlAuditor(issuersObj)

	ae := AggregateEngine{
		rootPath: tmpDir,
		issuers:  issuersObj,
		auditor:  auditor,
	}

	ca, caPrivKey := makeCA(t)
	issuer := issuersObj.InsertIssuer(ca, nil, nil, false)

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

func Test_SaveRevokedCertificateList(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "Test_SaveRevokedCertificateList")
	if err != nil {
		t.Error(err)
	}
	defer os.RemoveAll(tmpDir)

	issuersObj := rootprogram.NewMozillaIssuers()
	auditor := NewCrlAuditor(issuersObj)

	ae := AggregateEngine{
		rootPath: tmpDir,
		issuers:  issuersObj,
		auditor:  auditor,
	}

	issuer := types.NewIssuerFromString("issuerAKI")
	serials := []types.SerialAndReason{
		types.SerialAndReason{
			Serial: types.NewSerialFromHex("01"),
			Reason: 0,
		},
		types.SerialAndReason{
			Serial: types.NewSerialFromHex("02"),
			Reason: 255,
		},
		types.SerialAndReason{
			Serial: types.NewSerialFromHex("03"),
			Reason: 1,
		},
	}

	err = ae.StoreRevokedCertificateList(context.TODO(), issuer, serials)
	if err != nil {
		t.Error(err)
	}

	fileBytes, err := ioutil.ReadFile(filepath.Join(tmpDir, issuer.ID()))
	if err != nil {
		t.Error(err)
	}

	expected := []byte("0001\nff02\n0103\n")

	if !bytes.Equal(expected, fileBytes) {
		t.Fatalf("Data should match exactly - expected=[%+v] loaded=[%+v]", expected, fileBytes)
	}
}

func Test_IssuingDPMatching(t *testing.T) {
	// Certificate Revocation List (CRL):
	//         Version 2 (0x1)
	//         Signature Algorithm: ecdsa-with-SHA256
	//         Issuer: CN=Test CRL
	//         Last Update: Jul  1 16:02:05 2025 GMT
	//         Next Update: Jul 11 15:02:04 2025 GMT
	//         CRL extensions:
	//             X509v3 Issuing Distribution Point: critical
	//                 Full Name:
	//                   URI:http://example.com/1.crl
	//                   URI:http://example.com/2.crl
	//                   URI:http://example.com/2 final.crl
	//                   URI:http://example.com/?q=2 final final.crl
	//
	// No Revoked Certificates.
	//     Signature Algorithm: ecdsa-with-SHA256
	//     Signature Value:
	//         30:44:02:20:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
	//         00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
	//         02:20:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
	//         00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
	crlBlock := []byte(`-----BEGIN X509 CRL-----
MIIBNDCB3AIBATAKBggqhkjOPQQDAjATMREwDwYDVQQDEwhUZXN0IENSTBcNMjUw
NzAxMTYwMjA1WhcNMjUwNzExMTUwMjA0WjAAoIGVMIGSMIGPBgNVHRwBAf8EgYQw
gYGgf6B9hhhodHRwOi8vZXhhbXBsZS5jb20vMS5jcmyGGGh0dHA6Ly9leGFtcGxl
LmNvbS8yLmNybIYeaHR0cDovL2V4YW1wbGUuY29tLzIgZmluYWwuY3JshidodHRw
Oi8vZXhhbXBsZS5jb20vP3E9MiBmaW5hbCBmaW5hbC5jcmwwCgYIKoZIzj0EAwID
RwAwRAIgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACIAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
-----END X509 CRL-----`)

	crlPath, err := ioutil.TempFile("", "loadAndCheckSignatureOfCRL")
	if err != nil {
		t.Fatal(err)
	}

	defer os.Remove(crlPath.Name())

	if _, err := crlPath.Write(crlBlock); err != nil {
		t.Fatal(err)
	}
	if err := crlPath.Close(); err != nil {
		t.Fatal(err)
	}

	idpUrls, err := loadIssuingDistributionPointOfCRL(crlPath.Name())
	if err != nil {
		t.Fatal(err)
	}

	normalized := func(u string) string {
		parsed, err := url.Parse(u)
		if err != nil {
			t.Fatal(err)
		}
		return normalizedUrlString(parsed)
	}
	url1 := normalized("http://example.com/1.crl")
	url2 := normalized("http://example.com/2.crl")
	url3 := normalized("http://example.com/2%20final.crl")
	url4 := normalized("http://example.com/?q=2%20final%20final.crl")
	otherUrl := normalized("http://other.example.com")
	reversedIdpUrls := slices.Clone(idpUrls)
	slices.Reverse(reversedIdpUrls)

	for _, tc := range []struct {
		name        string
		fetchUrl    string
		idps        map[string][]string
		partitioned []string
		expectErr   string
	}{
		{"fetch URL not in the partitioned CRL URL set", url1,
			map[string][]string{url1: idpUrls}, []string{}, "Did not find matching URL"},
		{"fetch URL matches", url1,
			map[string][]string{url1: idpUrls}, []string{url1}, ""},
		{"fetch URL does not match", otherUrl,
			map[string][]string{otherUrl: idpUrls}, []string{otherUrl}, "Did not find matching URL"},
		{"fetch URL path is equivalent but not equal", url3,
			map[string][]string{url3: idpUrls}, []string{url3}, ""},
		{"fetch URL query is equivalent but not equal", url4,
			map[string][]string{url4: idpUrls}, []string{url4}, ""},
		{"another listed known CRL could not be loaded", url1,
			map[string][]string{url1: idpUrls}, []string{url1, url2}, ""},
		{"another listed known CRL is a mirror", url1,
			map[string][]string{url1: idpUrls, url2: reversedIdpUrls}, []string{url1, url2}, ""},
		{"another listed known CRL is a different partition", url1,
			map[string][]string{url1: idpUrls, url2: []string{url2}}, []string{url1, url2},
			"lists a different known CRL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			partitioned := map[string]bool{}
			for _, u := range tc.partitioned {
				partitioned[u] = true
			}
			err := checkIssuingDistributionPoint(tc.fetchUrl, tc.idps, partitioned)
			if tc.expectErr == "" && err != nil {
				t.Fatal(err)
			}
			if tc.expectErr != "" && (err == nil || !strings.Contains(err.Error(), tc.expectErr)) {
				t.Fatalf("Expected %q error, got %v", tc.expectErr, err)
			}
		})
	}
}

func makeCRLWithIssuingDP(t *testing.T, ca *x509.Certificate, caPrivKey interface{}, uris []string) []byte {
	t.Helper()

	// IssuingDistributionPoint ::= SEQUENCE { distributionPoint [0] { fullName [0] GeneralNames } }
	var names []byte
	for _, uri := range uris {
		name, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(uri)})
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, name...)
	}
	fullName, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: names})
	if err != nil {
		t.Fatal(err)
	}
	dpName, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: fullName})
	if err != nil {
		t.Fatal(err)
	}
	idp, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: dpName})
	if err != nil {
		t.Fatal(err)
	}

	// The certificate-transparency-go fork can't add CRL extensions, so use the standard library.
	stdCa, err := stdx509.ParseCertificate(ca.Raw)
	if err != nil {
		t.Fatal(err)
	}
	thisUpdate := time.Now().UTC()
	template := &stdx509.RevocationList{
		Number:          big.NewInt(1),
		ThisUpdate:      thisUpdate,
		NextUpdate:      thisUpdate.AddDate(0, 0, 1),
		ExtraExtensions: []stdpkix.Extension{{Id: []int{2, 5, 29, 28}, Critical: true, Value: idp}},
	}
	crlBytes, err := stdx509.CreateRevocationList(rand.Reader, template, stdCa, caPrivKey.(crypto.Signer))
	if err != nil {
		t.Fatal(err)
	}
	return crlBytes
}

func Test_aggregateCRLWorkerIssuingDPMirrors(t *testing.T) {
	tmpDir := t.TempDir()

	issuersObj := rootprogram.NewMozillaIssuers()
	auditor := NewCrlAuditor(issuersObj)
	ae := AggregateEngine{
		rootPath: filepath.Join(tmpDir, "revoked"),
		issuers:  issuersObj,
		auditor:  auditor,
	}

	ca, caPrivKey := makeCA(t)

	// Partition 1 is mirrored on two hosts, and its CRL lists both URLs. The CRL for
	// partition 2 lists the URL of partition 1 too, which is an error. The full CRL
	// has no issuingDistributionPoint, which is fine.
	p1a := "http://a.example.com/1.crl"
	p1b := "http://b.example.com/1.crl"
	p2 := "http://a.example.com/2.crl"
	full := "http://a.example.com/full.crl"
	thisUpdate := time.Now().UTC()
	crls := map[string][]byte{
		p1a:  makeCRLWithIssuingDP(t, ca, caPrivKey, []string{p1a, p1b}),
		p1b:  makeCRLWithIssuingDP(t, ca, caPrivKey, []string{p1a, p1b}),
		p2:   makeCRLWithIssuingDP(t, ca, caPrivKey, []string{p2, p1a}),
		full: makeCRL(t, ca, caPrivKey, thisUpdate, thisUpdate.AddDate(0, 0, 1)),
	}
	issuer := issuersObj.InsertIssuer(ca, []string{p1a, p1b, p2, full}, []string{p1a, p1b, p2}, true)

	tuple := types.IssuerCrlUrlPaths{Issuer: issuer}
	for i, u := range []string{p1a, p1b, p2, full} {
		crlUrl, _ := url.Parse(u)
		path := filepath.Join(tmpDir, fmt.Sprintf("%d.crl", i))
		if err := os.WriteFile(path, crls[u], 0644); err != nil {
			t.Fatal(err)
		}
		tuple.CrlUrlPaths = append(tuple.CrlUrlPaths, types.UrlPath{Url: *crlUrl, Path: path})
	}
	workChan := make(chan types.IssuerCrlUrlPaths, 1)
	workChan <- tuple
	close(workChan)

	var wg sync.WaitGroup
	wg.Add(1)
	ae.aggregateCRLWorker(context.TODO(), &wg, workChan)

	wrongDP := []string{}
	for _, e := range auditor.GetEntries() {
		if e.Kind == AuditKindWrongDP {
			wrongDP = append(wrongDP, e.Url)
		}
	}
	if !slices.Equal(wrongDP, []string{p2}) {
		t.Errorf("Expected only %s to have a wrong issuing DP, got %v", p2, wrongDP)
	}
}
