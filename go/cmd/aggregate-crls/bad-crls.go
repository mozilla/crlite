package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/hashicorp/go-metrics"
	"github.com/mozilla/crlite/go"
	"github.com/mozilla/crlite/go/rootprogram"
)

type BadCrlKind string

var (
	// A freshly downloaded CRL failed to parse or failed signature verification.
	// These are discarded by the downloader, so this is the only copy we keep.
	BadCrlKindFailedVerifyDownload BadCrlKind = "failed-verify-download"
	// A CRL already on disk failed to parse or failed signature verification.
	BadCrlKindFailedVerifyLocal BadCrlKind = "failed-verify-local"
	// A partitioned CRL has an issuingDistributionPoint extension that is
	// missing, unparseable, or does not match its fetch URL.
	BadCrlKindWrongIssuingDP BadCrlKind = "wrong-issuing-dp"
	// The revoked certificate entries of a CRL could not be decoded (e.g. an
	// invalid or repeated reason code).
	BadCrlKindFailedProcess BadCrlKind = "failed-process"
)

type BadCrlMetadata struct {
	Timestamp     time.Time
	Url           string
	Issuer        string
	IssuerSubject string
	Kind          BadCrlKind
	Error         string
	SourcePath    string
	SHA256Sum     string
	Size          int
}

// BadCrlReporter records CRLs that failed verification or processing. Each one
// is counted in the bad_crl metric. If rootPath is set, a copy of the
// CRL is also kept, along with a JSON file describing the failure, for later
// investigation. A nil *BadCrlReporter is valid and does nothing.
type BadCrlReporter struct {
	rootPath string
	issuers  *rootprogram.MozIssuers
}

func NewBadCrlReporter(rootPath string, issuers *rootprogram.MozIssuers) *BadCrlReporter {
	return &BadCrlReporter{
		rootPath: rootPath,
		issuers:  issuers,
	}
}

func (r *BadCrlReporter) Report(issuer types.Issuer, crlUrl *url.URL, srcPath string, kind BadCrlKind, cause error) {
	if r == nil {
		return
	}
	metrics.IncrCounter([]string{"bad_crl"}, 1)
	if r.rootPath != "" {
		r.save(issuer, crlUrl, srcPath, kind, cause)
	}
}

// Copies the CRL at srcPath to <rootPath>/<issuer>/<name>-<kind>.crl and
// writes the failure details to <rootPath>/<issuer>/<name>-<kind>.json. Errors
// are logged rather than returned, since saving is only a diagnostic aid.
func (r *BadCrlReporter) save(issuer types.Issuer, crlUrl *url.URL, srcPath string, kind BadCrlKind, cause error) {
	crlBytes, err := os.ReadFile(srcPath)
	if err != nil {
		glog.Warningf("[%s] Could not read bad CRL %s for saving: %s", issuer.ID(), srcPath, err)
		return
	}

	dir := filepath.Join(r.rootPath, issuer.ID())
	if err := os.MkdirAll(dir, permModeDir); err != nil {
		glog.Warningf("[%s] Could not make bad CRL directory: %s", issuer.ID(), err)
		return
	}

	stem := fmt.Sprintf("%s-%s", strings.TrimSuffix(makeFilenameFromUrl(*crlUrl), ".crl"), kind)
	crlPath := filepath.Join(dir, stem+".crl")
	metaPath := filepath.Join(dir, stem+".json")

	if err := os.WriteFile(crlPath, crlBytes, permMode); err != nil {
		glog.Warningf("[%s] Could not save bad CRL to %s: %s", issuer.ID(), crlPath, err)
		return
	}

	subject := ""
	if r.issuers != nil {
		subject, _ = r.issuers.GetSubjectForIssuer(issuer)
	}
	errStr := ""
	if cause != nil {
		errStr = cause.Error()
	}
	shasum := sha256.Sum256(crlBytes)
	meta := BadCrlMetadata{
		Timestamp:     time.Now().UTC(),
		Url:           crlUrl.String(),
		Issuer:        issuer.ID(),
		IssuerSubject: subject,
		Kind:          kind,
		Error:         errStr,
		SourcePath:    srcPath,
		SHA256Sum:     hex.EncodeToString(shasum[:]),
		Size:          len(crlBytes),
	}
	metaBytes, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		glog.Warningf("[%s] Could not encode bad CRL metadata: %s", issuer.ID(), err)
		return
	}
	if err := os.WriteFile(metaPath, metaBytes, permMode); err != nil {
		glog.Warningf("[%s] Could not save bad CRL metadata to %s: %s", issuer.ID(), metaPath, err)
		return
	}

	glog.Infof("[%s] Saved bad CRL (%s) from %s to %s", issuer.ID(), kind, crlUrl.String(), crlPath)
}
