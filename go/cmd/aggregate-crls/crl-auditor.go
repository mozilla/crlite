package main

import (
	"encoding/json"
	"io"
	"net/url"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/jcjones/ct-mapreduce/storage"
	"github.com/mozilla/crlite/go/rootprogram"
)

var (
	AuditKindFailedDownload     CrlAuditEntryKind = "Failed Download"
	AuditKindFailedProcessLocal CrlAuditEntryKind = "Failed Process Local"
	AuditKindFailedVerify       CrlAuditEntryKind = "Failed Verify"
	AuditKindNoRevocations      CrlAuditEntryKind = "Empty Revocation List"
	AuditKindOld                CrlAuditEntryKind = "Old"
)

type CrlAuditEntryKind string

type CrlAuditEntry struct {
	Timestamp     time.Time
	Url           string `json:",omitempty"`
	Path          string `json:",omitempty"`
	Age           string `json:",omitempty"`
	Issuer        storage.Issuer
	IssuerSubject string
	Kind          CrlAuditEntryKind
	Errors        []string `json:",omitempty"`
	DNSResults    []string `json:",omitempty"`
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

func (auditor *CrlAuditor) getSubject(issuer storage.Issuer) string {
	subject, err := auditor.issuers.GetSubjectForIssuer(issuer)
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

func (auditor *CrlAuditor) FailedDownload(issuer storage.Issuer, crlUrl *url.URL, dlAuditor *DownloadAuditor, err error) {
	auditor.mutex.Lock()
	defer auditor.mutex.Unlock()

	auditor.Entries = append(auditor.Entries, CrlAuditEntry{
		Timestamp:     time.Now().UTC(),
		Kind:          AuditKindFailedDownload,
		Url:           crlUrl.String(),
		Issuer:        issuer,
		IssuerSubject: auditor.getSubject(issuer),
		Errors:        append(dlAuditor.Errors(), err.Error()),
		DNSResults:    dlAuditor.DNSResults(),
	})
}

func (auditor *CrlAuditor) FailedVerifyUrl(issuer storage.Issuer, crlUrl *url.URL, dlAuditor *DownloadAuditor, err error) {
	auditor.mutex.Lock()
	defer auditor.mutex.Unlock()

	auditor.Entries = append(auditor.Entries, CrlAuditEntry{
		Timestamp:     time.Now().UTC(),
		Kind:          AuditKindFailedVerify,
		Url:           crlUrl.String(),
		Issuer:        issuer,
		IssuerSubject: auditor.getSubject(issuer),
		Errors:        append(dlAuditor.Errors(), err.Error()),
		DNSResults:    dlAuditor.DNSResults(),
	})
}

func (auditor *CrlAuditor) Old(issuer storage.Issuer, crlUrl *url.URL, age time.Duration) {
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

func (auditor *CrlAuditor) FailedVerifyPath(issuer storage.Issuer, crlPath string, err error) {
	auditor.mutex.Lock()
	defer auditor.mutex.Unlock()

	auditor.Entries = append(auditor.Entries, CrlAuditEntry{
		Timestamp:     time.Now().UTC(),
		Kind:          AuditKindFailedVerify,
		Path:          crlPath,
		Issuer:        issuer,
		IssuerSubject: auditor.getSubject(issuer),
		Errors:        []string{err.Error()},
	})
}
func (auditor *CrlAuditor) FailedProcessLocal(issuer storage.Issuer, crlPath string, err error) {
	auditor.mutex.Lock()
	defer auditor.mutex.Unlock()

	auditor.Entries = append(auditor.Entries, CrlAuditEntry{
		Timestamp:     time.Now().UTC(),
		Kind:          AuditKindFailedProcessLocal,
		Path:          crlPath,
		Issuer:        issuer,
		IssuerSubject: auditor.getSubject(issuer),
		Errors:        []string{err.Error()},
	})
}

func (auditor *CrlAuditor) NoRevocations(issuer storage.Issuer, crlPath string) {
	auditor.mutex.Lock()
	defer auditor.mutex.Unlock()

	auditor.Entries = append(auditor.Entries, CrlAuditEntry{
		Timestamp:     time.Now().UTC(),
		Kind:          AuditKindNoRevocations,
		Path:          crlPath,
		Issuer:        issuer,
		IssuerSubject: auditor.getSubject(issuer),
	})
}
