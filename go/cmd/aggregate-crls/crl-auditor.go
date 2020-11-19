package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/mozilla/crlite/go/downloader"
	"github.com/mozilla/crlite/go/rootprogram"
	"github.com/mozilla/crlite/go/storage"
)

var (
	AuditKindFailedDownload     CrlAuditEntryKind = "Failed Download"
	AuditKindFailedProcessLocal CrlAuditEntryKind = "Failed Process Local"
	AuditKindFailedVerify       CrlAuditEntryKind = "Failed Verify"
	AuditKindOlderThanLast      CrlAuditEntryKind = "Older Than Previous"
	AuditKindNoRevocations      CrlAuditEntryKind = "Empty Revocation List"
	AuditKindOld                CrlAuditEntryKind = "Very Old, Blocked"
	AuditKindExpired            CrlAuditEntryKind = "Expired, Allowed"
	AuditKindValid              CrlAuditEntryKind = "Valid, Processed"
)

type CrlAuditEntryKind string

type CrlAuditEntry struct {
	Timestamp      time.Time
	Url            string `json:",omitempty"`
	Path           string `json:",omitempty"`
	Age            string `json:",omitempty"`
	Issuer         downloader.DownloadIdentifier
	IssuerSubject  string
	Kind           CrlAuditEntryKind
	Errors         []string `json:",omitempty"`
	DNSResults     []string `json:",omitempty"`
	NumRevocations int      `json:",omitempty"`
	SHA256Sum      string   `json:",omitempty"`
}

type CrlAuditor struct {
	mutex   *sync.Mutex
	issuers *rootprogram.MozIssuers
	Entries []CrlAuditEntry
}

func NewCrlAuditor(issuers *rootprogram.MozIssuers) *CrlAuditor {
	return &CrlAuditor{
		mutex:   &sync.Mutex{},
		issuers: issuers,
		Entries: []CrlAuditEntry{},
	}
}

func (auditor *CrlAuditor) getSubject(identifier downloader.DownloadIdentifier) string {
	issuer, ok := identifier.(*storage.Issuer)
	if !ok {
		return ""
	}
	subject, err := auditor.issuers.GetSubjectForIssuer(*issuer)
	if err != nil {
		glog.Warningf("Could not get subject for issuer %s: %v", issuer.ID(), err)
		return ""
	}
	return subject
}

func (auditor *CrlAuditor) GetEntries() []CrlAuditEntry {
	return auditor.Entries
}

func (auditor *CrlAuditor) WriteReport(fd io.Writer) error {
	enc := json.NewEncoder(fd)
	auditor.mutex.Lock()
	defer auditor.mutex.Unlock()
	return enc.Encode(auditor)
}

func (auditor *CrlAuditor) FailedDownload(issuer downloader.DownloadIdentifier, crlUrl *url.URL, dlTracer *downloader.DownloadTracer, err error) {
	auditor.mutex.Lock()
	defer auditor.mutex.Unlock()

	auditor.Entries = append(auditor.Entries, CrlAuditEntry{
		Timestamp:     time.Now().UTC(),
		Kind:          AuditKindFailedDownload,
		Url:           crlUrl.String(),
		Issuer:        issuer,
		IssuerSubject: auditor.getSubject(issuer),
		Errors:        append(dlTracer.Errors(), err.Error()),
		DNSResults:    dlTracer.DNSResults(),
	})
}

func (auditor *CrlAuditor) FailedVerifyUrl(issuer downloader.DownloadIdentifier, crlUrl *url.URL, dlTracer *downloader.DownloadTracer, err error) {
	auditor.mutex.Lock()
	defer auditor.mutex.Unlock()

	auditor.Entries = append(auditor.Entries, CrlAuditEntry{
		Timestamp:     time.Now().UTC(),
		Kind:          AuditKindFailedVerify,
		Url:           crlUrl.String(),
		Issuer:        issuer,
		IssuerSubject: auditor.getSubject(issuer),
		Errors:        append(dlTracer.Errors(), err.Error()),
		DNSResults:    dlTracer.DNSResults(),
	})
}

func (auditor *CrlAuditor) FailedOlderThanPrevious(issuer downloader.DownloadIdentifier, crlUrl *url.URL, dlTracer *downloader.DownloadTracer, previous time.Time, this time.Time) {
	auditor.mutex.Lock()
	defer auditor.mutex.Unlock()

	err := fmt.Sprintf("Previous: %s, This Run: %s", previous, this)

	auditor.Entries = append(auditor.Entries, CrlAuditEntry{
		Timestamp:     time.Now().UTC(),
		Kind:          AuditKindOlderThanLast,
		Url:           crlUrl.String(),
		Issuer:        issuer,
		IssuerSubject: auditor.getSubject(issuer),
		Errors:        append(dlTracer.Errors(), err),
		DNSResults:    dlTracer.DNSResults(),
	})
}

func (auditor *CrlAuditor) Old(issuer downloader.DownloadIdentifier, crlUrl *url.URL, age time.Duration) {
	auditor.mutex.Lock()
	defer auditor.mutex.Unlock()

	auditor.Entries = append(auditor.Entries, CrlAuditEntry{
		Timestamp:     time.Now().UTC(),
		Kind:          AuditKindOld,
		Url:           crlUrl.String(),
		Issuer:        issuer,
		IssuerSubject: auditor.getSubject(issuer),
		Age:           age.String(),
	})
}

func (auditor *CrlAuditor) Expired(issuer downloader.DownloadIdentifier, crlUrl *url.URL, nextUpdate time.Time) {
	auditor.mutex.Lock()
	defer auditor.mutex.Unlock()

	auditor.Entries = append(auditor.Entries, CrlAuditEntry{
		Timestamp:     time.Now().UTC(),
		Kind:          AuditKindExpired,
		Url:           crlUrl.String(),
		Issuer:        issuer,
		IssuerSubject: auditor.getSubject(issuer),
		Errors:        []string{fmt.Sprintf("Expired, NextUpdate was %s", nextUpdate)},
	})
}

func (auditor *CrlAuditor) FailedVerifyPath(issuer downloader.DownloadIdentifier, crlUrl *url.URL, crlPath string, err error) {
	auditor.mutex.Lock()
	defer auditor.mutex.Unlock()

	auditor.Entries = append(auditor.Entries, CrlAuditEntry{
		Timestamp:     time.Now().UTC(),
		Kind:          AuditKindFailedVerify,
		Url:           crlUrl.String(),
		Path:          crlPath,
		Issuer:        issuer,
		IssuerSubject: auditor.getSubject(issuer),
		Errors:        []string{err.Error()},
	})
}
func (auditor *CrlAuditor) FailedProcessLocal(issuer downloader.DownloadIdentifier, crlUrl *url.URL, crlPath string, err error) {
	auditor.mutex.Lock()
	defer auditor.mutex.Unlock()

	auditor.Entries = append(auditor.Entries, CrlAuditEntry{
		Timestamp:     time.Now().UTC(),
		Kind:          AuditKindFailedProcessLocal,
		Url:           crlUrl.String(),
		Path:          crlPath,
		Issuer:        issuer,
		IssuerSubject: auditor.getSubject(issuer),
		Errors:        []string{err.Error()},
	})
}

func (auditor *CrlAuditor) NoRevocations(issuer downloader.DownloadIdentifier, crlUrl *url.URL, crlPath string) {
	auditor.mutex.Lock()
	defer auditor.mutex.Unlock()

	auditor.Entries = append(auditor.Entries, CrlAuditEntry{
		Timestamp:     time.Now().UTC(),
		Kind:          AuditKindNoRevocations,
		Url:           crlUrl.String(),
		Path:          crlPath,
		Issuer:        issuer,
		IssuerSubject: auditor.getSubject(issuer),
	})
}

func (auditor *CrlAuditor) ValidAndProcessed(issuer downloader.DownloadIdentifier, crlUrl *url.URL, crlPath string, numRevocations int, age time.Duration, sha256 []byte) {
	auditor.mutex.Lock()
	defer auditor.mutex.Unlock()

	auditor.Entries = append(auditor.Entries, CrlAuditEntry{
		Timestamp:      time.Now().UTC(),
		Kind:           AuditKindValid,
		Url:            crlUrl.String(),
		Path:           crlPath,
		Issuer:         issuer,
		IssuerSubject:  auditor.getSubject(issuer),
		Age:            age.String(),
		SHA256Sum:      hex.EncodeToString(sha256),
		NumRevocations: numRevocations,
	})
}
