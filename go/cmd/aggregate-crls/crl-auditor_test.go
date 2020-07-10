package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"testing"
	"time"

	"github.com/jcjones/ct-mapreduce/storage"
)

func assertEmptyList(t *testing.T, a *CrlAuditor) {
	t.Helper()
	idx := 0
	for _ = range a.GetEntries() {
		idx += 1
	}
	if idx != 0 {
		t.Errorf("Expected no entries, found %d", idx)
	}
}

func assertOnlyEntryInList(t *testing.T, a *CrlAuditor, entryKind CrlAuditEntryKind) *CrlAuditEntry {
	t.Helper()
	num := 0
	for _, entry := range a.GetEntries() {
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
	t.Helper()
	if ent.Url != url.String() {
		t.Errorf("Expected URL of %v got %v", url, ent.Url)
	}
	if ent.Issuer.ID() != issuer.ID() {
		t.Errorf("Expected Issuer of %v got %v", issuer, ent.Issuer)
	}
}

func assertEntryPathAndIssuer(t *testing.T, ent *CrlAuditEntry, issuer storage.Issuer, path string) {
	t.Helper()
	if ent.Path != path {
		t.Errorf("Expected Path of %v got %v", path, ent.Path)
	}
	if ent.Issuer.ID() != issuer.ID() {
		t.Errorf("Expected Issuer of %v got %v", issuer, ent.Issuer)
	}
}

type OutReport struct {
	Entries []CrlAuditEntry
}

func assertReportHasEntries(t *testing.T, r io.Reader, count int) {
	t.Helper()
	dec := json.NewDecoder(r)
	report := OutReport{}
	err := dec.Decode(&report)
	if err != nil {
		t.Error(err)
		return
	}
	if len(report.Entries) != count {
		t.Errorf("Expected %d entries but found %d", count, len(report.Entries))
	}
	for _, e := range report.Entries {
		// Check mandatory fields
		if e.Timestamp.IsZero() {
			t.Error("Timestamp should not be zero")
		}
		if len(e.Url) == 0 && len(e.Path) == 0 {
			t.Errorf("Either URL or Path must be set: %+v", e)
		}
		if e.Issuer.ID() == "" {
			t.Error("Issuer is mandatory")
		}
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

func Test_EmptyReport(t *testing.T) {
	auditor := NewCrlAuditor()
	assertEmptyList(t, auditor)

	var b bytes.Buffer
	err := auditor.WriteReport(&b)
	if err != nil {
		t.Error(err)
	}

	expected := []byte("{\"Entries\":[]}\n")
	if !bytes.Equal(b.Bytes(), expected) {
		t.Errorf("Expected %v got %v", expected, b.Bytes())
	}

	assertReportHasEntries(t, &b, 0)
}

func Test_SeveralFailures(t *testing.T) {
	auditor := NewCrlAuditor()
	issuer := storage.NewIssuerFromString("Test Corporation SA")
	url, _ := url.Parse("http://test/crl")

	assertEmptyList(t, auditor)

	age, err := time.ParseDuration("900h")
	if err != nil {
		t.Error(err)
	}

	auditor.Old(issuer, url, age)
	auditor.Old(issuer, url, age)
	auditor.Old(issuer, url, age)

	if len(auditor.GetEntries()) != 3 {
		t.Errorf("Expected 3 entries")
	}
	for _, e := range auditor.GetEntries() {
		assertEntryUrlAndIssuer(t, &e, issuer, url)
	}

	path := "/var/tmp/issuer.crl"

	auditor.NoRevocations(issuer, path)
	auditor.NoRevocations(issuer, path)
	auditor.NoRevocations(issuer, path)

	if len(auditor.GetEntries()) != 6 {
		t.Errorf("Expected 6 entries")
	}

	for i, e := range auditor.GetEntries() {
		if i < 3 {
			assertEntryUrlAndIssuer(t, &e, issuer, url)
		} else {
			assertEntryPathAndIssuer(t, &e, issuer, path)
		}
	}

	var b bytes.Buffer
	err = auditor.WriteReport(&b)
	if err != nil {
		t.Error(err)
	}

	assertReportHasEntries(t, &b, 6)
}
