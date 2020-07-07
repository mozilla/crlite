package main

import (
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
	Url    *url.URL
	Path   string
	Issuer storage.Issuer
	Kind   CrlAuditEntryKind
}

type CrlAuditor struct {
	mutex   *sync.Mutex
	entries []CrlAuditEntry
}

func NewCrlAuditor() *CrlAuditor {
	return &CrlAuditor{
		mutex: &sync.Mutex{},
	}
}

func (ae *CrlAuditor) GetEntries() <-chan CrlAuditEntry {
	c := make(chan CrlAuditEntry, len(ae.entries))
	for _, entry := range ae.entries {
		c <- entry
	}
	close(c)
	return c
}

func (ae *CrlAuditor) FailedDownload(issuer storage.Issuer, crlUrl *url.URL, err error) {
	ae.mutex.Lock()
	defer ae.mutex.Unlock()

	ae.entries = append(ae.entries, CrlAuditEntry{
		Kind:   AuditKindFailedDownload,
		Url:    crlUrl,
		Issuer: issuer,
	})
}

func (ae *CrlAuditor) FailedVerify(issuer storage.Issuer, crlUrl *url.URL, err error) {
	ae.mutex.Lock()
	defer ae.mutex.Unlock()

	ae.entries = append(ae.entries, CrlAuditEntry{
		Kind:   AuditKindFailedVerify,
		Url:    crlUrl,
		Issuer: issuer,
	})
}

func (ae *CrlAuditor) Old(issuer storage.Issuer, crlUrl *url.URL, age time.Duration) {
	ae.mutex.Lock()
	defer ae.mutex.Unlock()

	ae.entries = append(ae.entries, CrlAuditEntry{
		Kind:   AuditKindOld,
		Url:    crlUrl,
		Issuer: issuer,
	})
}

func (ae *CrlAuditor) FailedVerifyLocal(issuer storage.Issuer, crlPath string, err error) {
	ae.mutex.Lock()
	defer ae.mutex.Unlock()

	ae.entries = append(ae.entries, CrlAuditEntry{
		Kind:   AuditKindFailedVerifyLocal,
		Path:   crlPath,
		Issuer: issuer,
	})
}
func (ae *CrlAuditor) FailedProcessLocal(issuer storage.Issuer, crlPath string, err error) {
	ae.mutex.Lock()
	defer ae.mutex.Unlock()

	ae.entries = append(ae.entries, CrlAuditEntry{
		Kind:   AuditKindFailedProcessLocal,
		Path:   crlPath,
		Issuer: issuer,
	})
}

func (ae *CrlAuditor) NoRevocations(issuer storage.Issuer, crlPath string) {
	ae.mutex.Lock()
	defer ae.mutex.Unlock()

	ae.entries = append(ae.entries, CrlAuditEntry{
		Kind:   AuditKindNoRevocations,
		Path:   crlPath,
		Issuer: issuer,
	})
}
