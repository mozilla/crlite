package main

import (
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/jcjones/ct-mapreduce/storage"
)

func assertEmptyList(t *testing.T, a *CrlAuditor) {
	idx := 0
	for _ = range a.GetEntries() {
		idx += 1
	}
	if idx != 0 {
		t.Errorf("Expected no entries, found %d", idx)
	}
}

func assertOnlyEntryInList(t *testing.T, a *CrlAuditor, entryKind CrlAuditEntryKind) *CrlAuditEntry {
	num := 0
	for entry := range a.GetEntries() {
		num += 1
		if entry.Kind == entryKind {
			return &entry
		}
		if num > 1 {
			t.Errorf("More than one entry in list")
		}
	}
	t.Errorf("Entry type %v not in list of size %d", entryKind, num)
	return nil
}

func assertEntryUrlAndIssuer(t *testing.T, ent *CrlAuditEntry, issuer storage.Issuer, url *url.URL) {
	if ent.Url != url {
		t.Errorf("Expected URL of %v got %v", url, ent.Url)
	}
	if ent.Issuer.ID() != issuer.ID() {
		t.Errorf("Expected Issuer of %v got %v", issuer, ent.Issuer)
	}
}

func assertEntryPathAndIssuer(t *testing.T, ent *CrlAuditEntry, issuer storage.Issuer, path string) {
	if ent.Path != path {
		t.Errorf("Expected Path of %v got %v", path, ent.Path)
	}
	if ent.Issuer.ID() != issuer.ID() {
		t.Errorf("Expected Issuer of %v got %v", issuer, ent.Issuer)
	}
}

func Test_FailedDownload(t *testing.T) {
	auditor := NewCrlAuditor()
	issuer := storage.NewIssuerFromString("Test Corporation SA")
	url, _ := url.Parse("http://test/crl")

	assertEmptyList(t, auditor)

	auditor.FailedDownload(issuer, url, fmt.Errorf("bad error"))

	ent := assertOnlyEntryInList(t, auditor, AuditKindFailedDownload)
	assertEntryUrlAndIssuer(t, ent, issuer, url)
}

func Test_FailedVerify(t *testing.T) {
	auditor := NewCrlAuditor()
	issuer := storage.NewIssuerFromString("Test Corporation SA")
	url, _ := url.Parse("http://test/crl")

	assertEmptyList(t, auditor)

	auditor.FailedVerify(issuer, url, fmt.Errorf("bad error"))

	ent := assertOnlyEntryInList(t, auditor, AuditKindFailedVerify)
	assertEntryUrlAndIssuer(t, ent, issuer, url)
}

func Test_FailedProcessLocal(t *testing.T) {
	auditor := NewCrlAuditor()
	issuer := storage.NewIssuerFromString("Test Corporation SA")
	path := "crls/crl.pem"

	assertEmptyList(t, auditor)

	auditor.FailedProcessLocal(issuer, path, fmt.Errorf("bad error"))

	ent := assertOnlyEntryInList(t, auditor, AuditKindFailedProcessLocal)
	assertEntryPathAndIssuer(t, ent, issuer, path)
}

func Test_FailedVerifyLocal(t *testing.T) {
	auditor := NewCrlAuditor()
	issuer := storage.NewIssuerFromString("Test Corporation SA")
	path := "crls/crl.pem"

	assertEmptyList(t, auditor)

	auditor.FailedVerifyLocal(issuer, path, fmt.Errorf("bad error"))

	ent := assertOnlyEntryInList(t, auditor, AuditKindFailedVerifyLocal)
	assertEntryPathAndIssuer(t, ent, issuer, path)
}

func Test_FailedNoRevocations(t *testing.T) {
	auditor := NewCrlAuditor()
	issuer := storage.NewIssuerFromString("Test Corporation SA")
	path := "crls/crl.pem"

	assertEmptyList(t, auditor)

	auditor.NoRevocations(issuer, path)

	ent := assertOnlyEntryInList(t, auditor, AuditKindNoRevocations)
	assertEntryPathAndIssuer(t, ent, issuer, path)
}

func Test_FailedOld(t *testing.T) {
	auditor := NewCrlAuditor()
	issuer := storage.NewIssuerFromString("Test Corporation SA")
	url, _ := url.Parse("http://test/crl")

	assertEmptyList(t, auditor)

	age, err := time.ParseDuration("900h")
	if err != nil {
		t.Error(err)
	}

	auditor.Old(issuer, url, age)

	ent := assertOnlyEntryInList(t, auditor, AuditKindOld)
	assertEntryUrlAndIssuer(t, ent, issuer, url)
}
