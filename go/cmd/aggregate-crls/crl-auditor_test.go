package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/mozilla/crlite/go/downloader"
	"github.com/mozilla/crlite/go/rootprogram"
	"github.com/mozilla/crlite/go/storage"
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

func assertValidEntry(t *testing.T, ent *CrlAuditEntry) {
	t.Helper()
	// Check mandatory fields
	if ent.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
	if len(ent.Url) == 0 && len(ent.Path) == 0 {
		t.Errorf("Either URL or Path must be set: %+v", ent)
	}
	if ent.Issuer.ID() == "" {
		t.Error("Issuer is mandatory")
	}
	if ent.IssuerSubject == "" {
		t.Error("IssuerSubject is mandatory")
	}
	if ent.Kind != AuditKindNoRevocations && ent.Kind != AuditKindOld && ent.Kind != AuditKindValid {
		if len(ent.Errors) == 0 {
			t.Error("Expecting an error message")
		}
	}
	if ent.Kind == AuditKindValid && ent.NumRevocations < 1 {
		t.Error("Valid kinds should have at least one revocation")
	}
}

func assertOnlyEntryInList(t *testing.T, a *CrlAuditor, entryKind CrlAuditEntryKind) *CrlAuditEntry {
	t.Helper()
	num := 0
	for _, entry := range a.GetEntries() {
		num += 1
		assertValidEntry(t, &entry)
		if entry.Kind == entryKind {
			return &entry
		}
		if num > 1 {
			t.Errorf("More than one entry in list")
		}
	}
	t.Fatalf("Entry type %v not in list of size %d", entryKind, num)
	return nil
}

func assertEntryUrlAndIssuer(t *testing.T, ent *CrlAuditEntry, issuer storage.Issuer,
	issuersObj *rootprogram.MozIssuers, url *url.URL) {
	t.Helper()
	if ent.Url != url.String() {
		t.Errorf("Expected URL of %v got %v", url, ent.Url)
	}
	if ent.Issuer.ID() != issuer.ID() {
		t.Errorf("Expected Issuer of %v got %v", issuer, ent.Issuer)
	}
	expectedSubject, err := issuersObj.GetSubjectForIssuer(issuer)
	if err != nil {
		t.Error(err)
	}
	if ent.IssuerSubject != expectedSubject {
		t.Errorf("Expected Issuer Subject of %v got %v", expectedSubject, ent.IssuerSubject)
	}
	assertValidEntry(t, ent)
}

func assertEntryPathAndIssuer(t *testing.T, ent *CrlAuditEntry, issuer storage.Issuer,
	issuersObj *rootprogram.MozIssuers, path string) {
	t.Helper()
	if ent.Path != path {
		t.Errorf("Expected Path of %v got %v", path, ent.Path)
	}
	if ent.Issuer.ID() != issuer.ID() {
		t.Errorf("Expected Issuer of %v got %v", issuer, ent.Issuer)
	}
	expectedSubject, err := issuersObj.GetSubjectForIssuer(issuer)
	if err != nil {
		t.Error(err)
	}
	if ent.IssuerSubject != expectedSubject {
		t.Errorf("Expected Issuer Subject of %v got %v", expectedSubject, ent.IssuerSubject)
	}
	assertValidEntry(t, ent)
}

type testOutReport struct {
	Entries []testCrlAuditEntry
}
type testCrlAuditEntry struct {
	Timestamp     time.Time
	Url           string
	Path          string
	Age           string
	Issuer        string
	IssuerSubject string
	Kind          CrlAuditEntryKind
	Errors        []string
	DNSResults    []string
}

func (ent *testCrlAuditEntry) assertOkay(t *testing.T) {
	if ent.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
	if len(ent.Url) == 0 && len(ent.Path) == 0 {
		t.Errorf("Either URL or Path must be set: %+v", ent)
	}
	if ent.Issuer == "" {
		t.Error("Issuer is mandatory")
	}
	if ent.Kind != AuditKindNoRevocations && ent.Kind != AuditKindOld {
		if len(ent.Errors) == 0 {
			t.Error("Expecting an error message")
		}
	}
}

func assertAuditorReportHasEntries(t *testing.T, auditor *CrlAuditor, count int) {
	t.Helper()
	var b bytes.Buffer
	err := auditor.WriteReport(&b)
	if err != nil {
		t.Fatal(err)
	}

	dec := json.NewDecoder(&b)
	report := &testOutReport{}
	err = dec.Decode(report)
	if err != nil {
		t.Fatal(err)
	}

	if len(report.Entries) != count {
		t.Errorf("Expected %d audit report entries but found %d", count, len(report.Entries))
	}
	for _, e := range report.Entries {
		e.assertOkay(t)
	}
}

func Test_FailedDownload(t *testing.T) {
	issuersObj := rootprogram.NewMozillaIssuers()
	auditor := NewCrlAuditor(issuersObj)
	issuer := issuersObj.NewTestIssuerFromSubjectString("Test Corporation SA")
	url, _ := url.Parse("http://test/crl")

	assertEmptyList(t, auditor)

	auditor.FailedDownload(&issuer, url, downloader.NewDownloadTracer(), fmt.Errorf("bad error"))

	ent := assertOnlyEntryInList(t, auditor, AuditKindFailedDownload)
	assertEntryUrlAndIssuer(t, ent, issuer, issuersObj, url)
}

func Test_FailedVerify(t *testing.T) {
	issuersObj := rootprogram.NewMozillaIssuers()
	auditor := NewCrlAuditor(issuersObj)
	issuer := issuersObj.NewTestIssuerFromSubjectString("Test Corporation SA")
	url, _ := url.Parse("http://test/crl")

	assertEmptyList(t, auditor)

	auditor.FailedVerifyUrl(&issuer, url, downloader.NewDownloadTracer(), fmt.Errorf("bad error"))

	ent := assertOnlyEntryInList(t, auditor, AuditKindFailedVerify)
	assertEntryUrlAndIssuer(t, ent, issuer, issuersObj, url)
}

func Test_FailedProcessLocal(t *testing.T) {
	issuersObj := rootprogram.NewMozillaIssuers()
	auditor := NewCrlAuditor(issuersObj)
	issuer := issuersObj.NewTestIssuerFromSubjectString("Test Corporation SA")
	path := "crls/crl.pem"

	assertEmptyList(t, auditor)

	auditor.FailedProcessLocal(&issuer, path, fmt.Errorf("bad error"))

	ent := assertOnlyEntryInList(t, auditor, AuditKindFailedProcessLocal)
	assertEntryPathAndIssuer(t, ent, issuer, issuersObj, path)
}

func Test_FailedVerifyLocal(t *testing.T) {
	issuersObj := rootprogram.NewMozillaIssuers()
	auditor := NewCrlAuditor(issuersObj)
	issuer := issuersObj.NewTestIssuerFromSubjectString("Test Corporation SA")
	path := "crls/crl.pem"

	assertEmptyList(t, auditor)

	auditor.FailedVerifyPath(&issuer, path, fmt.Errorf("bad error"))

	ent := assertOnlyEntryInList(t, auditor, AuditKindFailedVerify)
	assertEntryPathAndIssuer(t, ent, issuer, issuersObj, path)
}

func Test_FailedNoRevocations(t *testing.T) {
	issuersObj := rootprogram.NewMozillaIssuers()
	auditor := NewCrlAuditor(issuersObj)
	issuer := issuersObj.NewTestIssuerFromSubjectString("Test Corporation SA")
	path := "crls/crl.pem"

	assertEmptyList(t, auditor)

	auditor.NoRevocations(&issuer, path)

	ent := assertOnlyEntryInList(t, auditor, AuditKindNoRevocations)
	assertEntryPathAndIssuer(t, ent, issuer, issuersObj, path)
}

func Test_FailedOld(t *testing.T) {
	issuersObj := rootprogram.NewMozillaIssuers()
	auditor := NewCrlAuditor(issuersObj)
	issuer := issuersObj.NewTestIssuerFromSubjectString("Test Corporation SA")
	url, _ := url.Parse("http://test/crl")

	assertEmptyList(t, auditor)

	age, err := time.ParseDuration("900h")
	if err != nil {
		t.Error(err)
	}

	auditor.Old(&issuer, url, age)

	ent := assertOnlyEntryInList(t, auditor, AuditKindOld)
	assertEntryUrlAndIssuer(t, ent, issuer, issuersObj, url)
}

func Test_FailedOlderThanPrevious(t *testing.T) {
	issuersObj := rootprogram.NewMozillaIssuers()
	auditor := NewCrlAuditor(issuersObj)
	issuer := issuersObj.NewTestIssuerFromSubjectString("Test Corporation SA")
	url, _ := url.Parse("http://test/crl")

	assertEmptyList(t, auditor)

	auditor.FailedOlderThanPrevious(&issuer, url, downloader.NewDownloadTracer(), time.Now(), time.Now().AddDate(0, 0, -1))

	ent := assertOnlyEntryInList(t, auditor, AuditKindOlderThanLast)
	assertEntryUrlAndIssuer(t, ent, issuer, issuersObj, url)
}

func Test_FailedExpired(t *testing.T) {
	issuersObj := rootprogram.NewMozillaIssuers()
	auditor := NewCrlAuditor(issuersObj)
	issuer := issuersObj.NewTestIssuerFromSubjectString("Test Corporation SA")
	url, _ := url.Parse("http://test/crl")

	assertEmptyList(t, auditor)

	auditor.Expired(&issuer, url, time.Now().AddDate(0, 0, -1))

	ent := assertOnlyEntryInList(t, auditor, AuditKindExpired)
	assertEntryUrlAndIssuer(t, ent, issuer, issuersObj, url)
}

func Test_Valid(t *testing.T) {
	issuersObj := rootprogram.NewMozillaIssuers()
	auditor := NewCrlAuditor(issuersObj)
	issuer := issuersObj.NewTestIssuerFromSubjectString("Test Corporation SA")
	path := "/var/tmp/issuer.crl"

	assertEmptyList(t, auditor)

	age, err := time.ParseDuration("900h")
	if err != nil {
		t.Error(err)
	}

	auditor.ValidAndProcessed(&issuer, path, 42, age, []byte{0x42})

	ent := assertOnlyEntryInList(t, auditor, AuditKindValid)
	assertEntryPathAndIssuer(t, ent, issuer, issuersObj, path)
}

func Test_EmptyReport(t *testing.T) {
	issuersObj := rootprogram.NewMozillaIssuers()
	auditor := NewCrlAuditor(issuersObj)
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

	assertAuditorReportHasEntries(t, auditor, 0)
}

func Test_SeveralFailures(t *testing.T) {
	issuersObj := rootprogram.NewMozillaIssuers()
	auditor := NewCrlAuditor(issuersObj)
	issuer := issuersObj.NewTestIssuerFromSubjectString("Test Corporation SA")
	url, _ := url.Parse("http://test/crl")

	assertEmptyList(t, auditor)

	age, err := time.ParseDuration("900h")
	if err != nil {
		t.Error(err)
	}

	auditor.Old(&issuer, url, age)
	auditor.Old(&issuer, url, age)
	auditor.Old(&issuer, url, age)

	if len(auditor.GetEntries()) != 3 {
		t.Errorf("Expected 3 entries")
	}
	for _, e := range auditor.GetEntries() {
		assertEntryUrlAndIssuer(t, &e, issuer, issuersObj, url)
	}

	path := "/var/tmp/issuer.crl"

	auditor.NoRevocations(&issuer, path)
	auditor.NoRevocations(&issuer, path)
	auditor.NoRevocations(&issuer, path)

	if len(auditor.GetEntries()) != 6 {
		t.Errorf("Expected 6 entries")
	}

	for i, e := range auditor.GetEntries() {
		if i < 3 {
			assertEntryUrlAndIssuer(t, &e, issuer, issuersObj, url)
		} else {
			assertEntryPathAndIssuer(t, &e, issuer, issuersObj, path)
		}
	}

	assertAuditorReportHasEntries(t, auditor, 6)
}
