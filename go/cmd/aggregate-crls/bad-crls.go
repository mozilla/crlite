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

// BadCrlSaver keeps copies of CRLs that failed verification or processing,
// along with a JSON file describing the failure, for later investigation.
// A nil *BadCrlSaver is valid and saves nothing.
type BadCrlSaver struct {
	rootPath string
	issuers  *rootprogram.MozIssuers
}

func NewBadCrlSaver(rootPath string, issuers *rootprogram.MozIssuers) *BadCrlSaver {
	return &BadCrlSaver{
		rootPath: rootPath,
		issuers:  issuers,
	}
}

// Save copies the CRL at srcPath to <rootPath>/<issuer>/<name>-<kind>.crl and
// writes the failure details to <rootPath>/<issuer>/<name>-<kind>.json. Errors
// are logged rather than returned, since saving is only a diagnostic aid.
func (s *BadCrlSaver) Save(issuer types.Issuer, crlUrl *url.URL, srcPath string, kind BadCrlKind, cause error) {
	if s == nil {
		return
	}

	crlBytes, err := os.ReadFile(srcPath)
	if err != nil {
		glog.Warningf("[%s] Could not read bad CRL %s for saving: %s", issuer.ID(), srcPath, err)
		return
	}

	dir := filepath.Join(s.rootPath, issuer.ID())
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
	if s.issuers != nil {
		subject, _ = s.issuers.GetSubjectForIssuer(issuer)
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
