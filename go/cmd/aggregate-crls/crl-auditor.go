package main

import (
	"encoding/json"
	"io"
	"net/url"
	"sync"
	"time"

	"github.com/jcjones/ct-mapreduce/storage"
)

var (
	AuditKindFailedDownload     CrlAuditEntryKind = "Failed Download"
	AuditKindFailedProcessLocal CrlAuditEntryKind = "Failed Process Local"
	AuditKindFailedVerify       CrlAuditEntryKind = "Failed Verify"
	AuditKindFailedVerifyLocal  CrlAuditEntryKind = "Failed Verify Local"
	AuditKindNoRevocations      CrlAuditEntryKind = "No NoRevocations"
	AuditKindOld                CrlAuditEntryKind = "Old"
)

type CrlAuditEntryKind string

type CrlAuditEntry struct {
	Timestamp time.Time
	Url       string `json:",omitempty"`
	Path      string `json:",omitempty"`
	Age       string `json:",omitempty"`
	Issuer    storage.Issuer
	Kind      CrlAuditEntryKind
}

type CrlAuditor struct {
	mutex   *sync.Mutex `json:"-"`
	Entries []CrlAuditEntry
}

func NewCrlAuditor() *CrlAuditor {
	return &CrlAuditor{
		mutex:   &sync.Mutex{},
		Entries: []CrlAuditEntry{},
	}
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

func (auditor *CrlAuditor) FailedDownload(issuer storage.Issuer, crlUrl *url.URL, err error) {
	auditor.mutex.Lock()
	defer auditor.mutex.Unlock()

	auditor.Entries = append(auditor.Entries, CrlAuditEntry{
		Timestamp: time.Now().UTC(),
		Kind:      AuditKindFailedDownload,
		Url:       crlUrl.String(),
		Issuer:    issuer,
	})
}

func (auditor *CrlAuditor) FailedVerify(issuer storage.Issuer, crlUrl *url.URL, err error) {
	auditor.mutex.Lock()
	defer auditor.mutex.Unlock()

	auditor.Entries = append(auditor.Entries, CrlAuditEntry{
		Timestamp: time.Now().UTC(),
		Kind:      AuditKindFailedVerify,
		Url:       crlUrl.String(),
		Issuer:    issuer,
	})
}

func (auditor *CrlAuditor) Old(issuer storage.Issuer, crlUrl *url.URL, age time.Duration) {
	auditor.mutex.Lock()
	defer auditor.mutex.Unlock()

	auditor.Entries = append(auditor.Entries, CrlAuditEntry{
		Timestamp: time.Now().UTC(),
		Kind:      AuditKindOld,
		Url:       crlUrl.String(),
		Issuer:    issuer,
		Age:       age.String(),
	})
}

func (auditor *CrlAuditor) FailedVerifyLocal(issuer storage.Issuer, crlPath string, err error) {
	auditor.mutex.Lock()
	defer auditor.mutex.Unlock()

	auditor.Entries = append(auditor.Entries, CrlAuditEntry{
		Timestamp: time.Now().UTC(),
		Kind:      AuditKindFailedVerifyLocal,
		Path:      crlPath,
		Issuer:    issuer,
	})
}
func (auditor *CrlAuditor) FailedProcessLocal(issuer storage.Issuer, crlPath string, err error) {
	auditor.mutex.Lock()
	defer auditor.mutex.Unlock()

	auditor.Entries = append(auditor.Entries, CrlAuditEntry{
		Timestamp: time.Now().UTC(),
		Kind:      AuditKindFailedProcessLocal,
		Path:      crlPath,
		Issuer:    issuer,
	})
}

func (auditor *CrlAuditor) NoRevocations(issuer storage.Issuer, crlPath string) {
	auditor.mutex.Lock()
	defer auditor.mutex.Unlock()

	auditor.Entries = append(auditor.Entries, CrlAuditEntry{
		Timestamp: time.Now().UTC(),
		Kind:      AuditKindNoRevocations,
		Path:      crlPath,
		Issuer:    issuer,
	})
}
