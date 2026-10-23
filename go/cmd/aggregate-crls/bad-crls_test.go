package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/x509/pkix"
	"github.com/mozilla/crlite/go"
	"github.com/mozilla/crlite/go/rootprogram"
)

func badCrlStem(root string, issuer types.Issuer, crlUrl *url.URL, kind BadCrlKind) string {
	name := strings.TrimSuffix(makeFilenameFromUrl(*crlUrl), ".crl")
	return filepath.Join(root, issuer.ID(), name+"-"+string(kind))
}

func assertBadCrlSaved(t *testing.T, root string, issuer types.Issuer, crlUrl *url.URL,
	kind BadCrlKind, expected []byte) {
	t.Helper()
	stem := badCrlStem(root, issuer, crlUrl, kind)

	crlBytes, err := os.ReadFile(stem + ".crl")
	if err != nil {
		t.Fatalf("Expected a saved %s CRL: %s", kind, err)
	}
	if !bytes.Equal(crlBytes, expected) {
		t.Errorf("Saved %s CRL didn't match the expected bytes", kind)
	}

	metaBytes, err := os.ReadFile(stem + ".json")
	if err != nil {
		t.Fatalf("Expected saved %s metadata: %s", kind, err)
	}
	var meta BadCrlMetadata
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		t.Fatal(err)
	}
	shasum := sha256.Sum256(expected)
	if meta.Kind != kind || meta.Url != crlUrl.String() || meta.Issuer != issuer.ID() ||
		meta.SHA256Sum != hex.EncodeToString(shasum[:]) || meta.Size != len(expected) ||
		meta.Error == "" {
		t.Errorf("Unexpected metadata: %+v", meta)
	}
}

func assertBadCrlNotSaved(t *testing.T, root string, issuer types.Issuer, crlUrl *url.URL, kind BadCrlKind) {
	t.Helper()
	stem := badCrlStem(root, issuer, crlUrl, kind)
	if _, err := os.Stat(stem + ".crl"); !os.IsNotExist(err) {
		t.Errorf("Did not expect a saved %s CRL: %v", kind, err)
	}
}

func Test_BadCrlSaverNil(t *testing.T) {
	var saver *BadCrlSaver
	crlUrl, _ := url.Parse("http://example.com/crl")
	saver.Save(types.NewIssuerFromString("issuer"), crlUrl, "/nonexistent", BadCrlKindFailedProcess, nil)
}

func Test_crlFetchWorkerProcessOneSavesBadCrls(t *testing.T) {
	tmpDir := t.TempDir()
	*crlpath = filepath.Join(tmpDir, "crls")
	badDir := filepath.Join(tmpDir, "bad-crls")

	issuersObj := rootprogram.NewMozillaIssuers()
	ae := AggregateEngine{
		rootPath: filepath.Join(tmpDir, "revoked"),
		issuers:  issuersObj,
		auditor:  NewCrlAuditor(issuersObj),
		badCrls:  NewBadCrlSaver(badDir, issuersObj),
	}

	ca, _ := makeCA(t)
	_, otherCaPrivKey := makeCA(t)
	issuer := issuersObj.InsertIssuer(ca, nil, nil, false)

	thisUpdate := time.Now().UTC()
	nextUpdate := thisUpdate.AddDate(0, 0, 1)
	misSignedCrlBytes := makeCRL(t, ca, otherCaPrivKey, thisUpdate, nextUpdate)

	server := hostCRL(t, misSignedCrlBytes)
	defer server.Close()
	crlUrl, _ := url.Parse(server.URL + "/crl")

	// No local copy, so the mis-signed download is the only one saved
	path, err := ae.crlFetchWorkerProcessOne(context.TODO(), *crlUrl, issuer)
	if err == nil || path != "" {
		t.Fatalf("Expected a verification failure, got path=%q err=%v", path, err)
	}
	assertBadCrlSaved(t, badDir, issuer, crlUrl, BadCrlKindFailedVerifyDownload, misSignedCrlBytes)
	assertBadCrlNotSaved(t, badDir, issuer, crlUrl, BadCrlKindFailedVerifyLocal)

	// A corrupt local copy is saved too when the fallback to it fails
	corruptBytes := []byte("not a CRL")
	localPath := filepath.Join(*crlpath, issuer.ID(), makeFilenameFromUrl(*crlUrl))
	if err := os.WriteFile(localPath, corruptBytes, permMode); err != nil {
		t.Fatal(err)
	}
	path, err = ae.crlFetchWorkerProcessOne(context.TODO(), *crlUrl, issuer)
	if err == nil || path != "" {
		t.Fatalf("Expected a verification failure, got path=%q err=%v", path, err)
	}
	assertBadCrlSaved(t, badDir, issuer, crlUrl, BadCrlKindFailedVerifyDownload, misSignedCrlBytes)
	assertBadCrlSaved(t, badDir, issuer, crlUrl, BadCrlKindFailedVerifyLocal, corruptBytes)
}

func Test_aggregateCRLWorkerSavesBadCrls(t *testing.T) {
	tmpDir := t.TempDir()
	badDir := filepath.Join(tmpDir, "bad-crls")

	issuersObj := rootprogram.NewMozillaIssuers()
	ae := AggregateEngine{
		rootPath: filepath.Join(tmpDir, "revoked"),
		issuers:  issuersObj,
		auditor:  NewCrlAuditor(issuersObj),
		badCrls:  NewBadCrlSaver(badDir, issuersObj),
	}

	ca, caPrivKey := makeCA(t)
	// Partitioned, so the CRL must have a matching issuingDistributionPoint
	crlUrlStr := "http://example.com/1.crl"
	issuer := issuersObj.InsertIssuer(ca, []string{crlUrlStr}, []string{crlUrlStr}, true)

	keyCompromise, err := asn1.Marshal(asn1.Enumerated(1))
	if err != nil {
		t.Fatal(err)
	}
	// A repeated reason code causes processCRL to fail
	revoked := []pkix.RevokedCertificate{
		pkix.RevokedCertificate{
			SerialNumber:   big.NewInt(int64(123456789)),
			RevocationTime: time.Now().UTC(),
			Extensions: []pkix.Extension{
				pkix.Extension{Id: []int{2, 5, 29, 21}, Value: keyCompromise},
				pkix.Extension{Id: []int{2, 5, 29, 21}, Value: keyCompromise},
			},
		},
	}
	thisUpdate := time.Now().UTC()
	crlBytes, err := ca.CreateCRL(rand.Reader, caPrivKey, revoked, thisUpdate, thisUpdate.AddDate(0, 0, 1))
	if err != nil {
		t.Fatal(err)
	}
	crlPath := filepath.Join(tmpDir, "test.crl")
	if err := os.WriteFile(crlPath, crlBytes, permMode); err != nil {
		t.Fatal(err)
	}

	crlUrl, _ := url.Parse(crlUrlStr)
	workChan := make(chan types.IssuerCrlUrlPaths, 1)
	workChan <- types.IssuerCrlUrlPaths{
		Issuer:      issuer,
		CrlUrlPaths: []types.UrlPath{types.UrlPath{Url: *crlUrl, Path: crlPath}},
	}
	close(workChan)

	var wg sync.WaitGroup
	wg.Add(1)
	ae.aggregateCRLWorker(context.TODO(), &wg, workChan)

	assertBadCrlSaved(t, badDir, issuer, crlUrl, BadCrlKindWrongIssuingDP, crlBytes)
	assertBadCrlSaved(t, badDir, issuer, crlUrl, BadCrlKindFailedProcess, crlBytes)
	assertBadCrlNotSaved(t, badDir, issuer, crlUrl, BadCrlKindFailedVerifyLocal)
}
