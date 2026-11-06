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
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/x509/pkix"
	"github.com/hashicorp/go-metrics"
	"github.com/mozilla/crlite/go"
	"github.com/mozilla/crlite/go/config"
	"github.com/mozilla/crlite/go/engine"
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

func Test_BadCrlReporterNil(t *testing.T) {
	var reporter *BadCrlReporter
	crlUrl, _ := url.Parse("http://example.com/crl")
	reporter.Report(types.NewIssuerFromString("issuer"), crlUrl, "/nonexistent", BadCrlKindFailedProcess, nil)
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
		badCrls:  NewBadCrlReporter(badDir, issuersObj),
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
		badCrls:  NewBadCrlReporter(badDir, issuersObj),
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

func Test_BadCrlReporterStatsd(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	ctconfig := config.NewCTConfig()
	*ctconfig.StatsDHost = "127.0.0.1"
	*ctconfig.StatsDPort = conn.LocalAddr().(*net.UDPAddr).Port
	engine.PrepareTelemetry("aggregate-crls", ctconfig)

	crlPath := filepath.Join(t.TempDir(), "test.crl")
	if err := os.WriteFile(crlPath, []byte("not a CRL"), permMode); err != nil {
		t.Fatal(err)
	}
	crlUrl, _ := url.Parse("http://example.com/crl")
	// Metrics are counted even when bad CRLs aren't saved
	reporter := NewBadCrlReporter("", nil)
	reporter.Report(types.NewIssuerFromString("issuer"), crlUrl, crlPath, BadCrlKindFailedProcess, nil)
	// Shutting down drops unsent metrics, as happens when aggregate-crls exits
	engine.FlushTelemetry(ctconfig)
	metrics.Shutdown()

	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("Expected a statsd packet: %s", err)
	}
	expected := "aggregate-crls.bad_crl:1.000000|c"
	if !strings.Contains(string(buf[:n]), expected) {
		t.Errorf("Expected %q in statsd packet %q", expected, string(buf[:n]))
	}
}
