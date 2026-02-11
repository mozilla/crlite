package rootprogram

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	newx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/mozilla/crlite/go"
)

const (
	kFirstTwoLines = `SHA_256_Fingerprint,X.509_Certificate_PEM,RecordType.Name,Revocation_Status__c,Full_CRL_Issued_By_This_CA,JSON_Array_of_Partitioned_CRLs
69729B8E15A86EFC177A57AFB7171DFC64ADD28C2FCA8CF1507E34453CCB1470,"-----BEGIN CERTIFICATE-----
MIICGzCCAaGgAwIBAgIQQdKd0XLq7qeAwSxs6S+HUjAKBggqhkjOPQQDAzBPMQsw
CQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2gg
R3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMjAeFw0yMDA5MDQwMDAwMDBaFw00
MDA5MTcxNjAwMDBaME8xCzAJBgNVBAYTAlVTMSkwJwYDVQQKEyBJbnRlcm5ldCBT
ZWN1cml0eSBSZXNlYXJjaCBHcm91cDEVMBMGA1UEAxMMSVNSRyBSb290IFgyMHYw
EAYHKoZIzj0CAQYFK4EEACIDYgAEzZvVn4CDCuwJSvMWSj5cz3es3mcFDR0HttwW
+1qLFNvicWDEukWVEYmO6gbf9yoWHKS5xcUy4APgHoIYOIvXRdgKam7mAHf7AlF9
ItgKbppbd9/w+kHsOdx1ymgHDB/qo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0T
AQH/BAUwAwEB/zAdBgNVHQ4EFgQUfEKWrt5LSDv6kviejM9ti6lyN5UwCgYIKoZI
zj0EAwMDaAAwZQIwe3lORlCEwkSHRhtFcP9Ymd70/aTSVaYgLXTWNLxBo1BfASdW
tL4ndQavEi51mI38AjEAi/V3bNTIZargCyzuFJ0nN6T5U6VR5CmD1/iQMVtCnwr1
/q4AaOeMSQ+2b1tbFfLn
-----END CERTIFICATE-----",Root Certificate,,http://x2.c.lencr.org/,
AC1274542267F17B525535B5563BF731FEBB182533B46A82DC869CB64EB528C0,"-----BEGIN CERTIFICATE-----
MIICtTCCAjugAwIBAgIQfo8UX4exWTMtf9QIK4JraTAKBggqhkjOPQQDAzBPMQsw
CQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2gg
R3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMjAeFw0yNDAzMTMwMDAwMDBaFw0y
NzAzMTIyMzU5NTlaMDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNy
eXB0MQswCQYDVQQDEwJFODB2MBAGByqGSM49AgEGBSuBBAAiA2IABNFl8l7cS7QM
ApzSsvru6WyrOq44ofTUOTIzxULUzDMMNMchIJBwXOhiLxxxs0LXeb5GDcHbR6ET
oMffgSZjO9SNHfY9gjMy9vQr5/WWOrQTZxh7az6NSNnq3u2ubT6HTKOB+DCB9TAO
BgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMBIG
A1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFI8NE6L2Ln7RUGwzGDhdWY4jcpHK
MB8GA1UdIwQYMBaAFHxClq7eS0g7+pL4nozPbYupcjeVMDIGCCsGAQUFBwEBBCYw
JDAiBggrBgEFBQcwAoYWaHR0cDovL3gyLmkubGVuY3Iub3JnLzATBgNVHSAEDDAK
MAgGBmeBDAECATAnBgNVHR8EIDAeMBygGqAYhhZodHRwOi8veDIuYy5sZW5jci5v
cmcvMAoGCCqGSM49BAMDA2gAMGUCMQClsUNJdX36GE+o2yDf7L02m3P3ElVWRLls
5ZyLYPjcNamBxRB9gZYoj24mGZtP3GkCMASZcALg6kpScomqIIjVHXRUQ500cdl4
4n7fhxwokLo/lVlO8YyHwAi7ejTHtvw9Vg==
-----END CERTIFICATE-----",Intermediate Certificate,Not Revoked,,`

	kFirstTwoLinesIssuerID = "iFvwVyJSxnQdyaUvUERIf-8qk7gRze3612JMwoO3zdU="

	kFirstTwoLinesSubject = "CN=E8,O=Let's Encrypt,C=US"

	kFirstTwoLinesMalformed = `"CA Owner","Parent Name","Certificate Name","Certificate Issuer Common Name","Certificate Issuer Organization","Certificate Issuer Organizational Unit","Certificate Subject Common Name","Certificate Subject Organization","Certificate Serial Number","SHA-1 Fingerprint","SHA-256 Fingerprint","Subject + SPKI SHA256","Technically Constrained","Valid From [GMT]","Valid To [GMT]","CRL URL(s)","Public Key Algorithm","Signature Hash Algorithm","Key Usage","Extended Key Usage","CP/CPS Same As Parent","Certificate Policy (CP)","Certification Practice Statement (CPS)","Audits Same As Parent","Standard Audit","BR Audit","Auditor","Standard Audit Statement Dt","Management Assertions By","Comments","PEM"
"AC Camerfirma, S.A.","AC Camerfirma","RACER","AC Camerfirma","AC Camerfirma SA","","RACER","AC Camerfirma SA","01","F82701F8E04770F3448C19070F9B2158B16621A0","F1712177935DBA40BDBD99C5F753319CF6293549B7284741E43916AD3BFBDD75","80C14510C26519770718D4086A713C32DBC2209FF30B2AAA36523CC310424096","false","2003 Dec 04","2023 Dec 04","http://crl.camerfirma.com/racer.crl","RSA 2047 bits","SHA1WithRSA","Digital Signature, Certificate Sign, CRL Sign","(not present)","TRUE","","","TRUE","","","","","","",""`
)

func loadSampleIssuers(content string) (*MozIssuers, error) {
	tmpfile, err := ioutil.TempFile("", "loadSampleIssuers")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpfile.Name())

	err = ioutil.WriteFile(tmpfile.Name(), []byte(content), 0644)
	if err != nil {
		return nil, err
	}

	mi := NewMozillaIssuers()
	return mi, mi.LoadFromDisk(tmpfile.Name())
}

func makeCert(t *testing.T, issuerDN string, expDate string, serial *big.Int) *newx509.Certificate {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Error(err)
		return nil
	}

	notAfter, err := time.Parse("2006-01-02", expDate)
	if err != nil {
		t.Fatalf("Programmer error on timestamp %s: %v", expDate, err)
	}
	notBefore := notAfter.AddDate(-1, 0, 0)

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: issuerDN,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		IsCA:      true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template,
		privKey.Public(), privKey)
	if err != nil {
		t.Error(err)
		return nil
	}

	obj, err := newx509.ParseCertificate(certBytes)
	if err != nil {
		t.Error(err)
		return nil
	}

	return obj
}

func Test_GetIssuers(t *testing.T) {
	mi, err := loadSampleIssuers(kFirstTwoLines)
	if err != nil {
		t.Fatal(err)
	}

	issuers := mi.GetIssuers()
	if len(issuers) != 1 {
		t.Fatal("Expecting one issuer")
	}

	if issuers[0].ID() != kFirstTwoLinesIssuerID {
		t.Errorf("Unexpected issuer SPKI, got: [%s]", issuers[0].ID())
	}
}

func Test_IsIssuerInProgram(t *testing.T) {
	mi, err := loadSampleIssuers(kFirstTwoLines)
	if err != nil {
		t.Fatal(err)
	}

	if mi.IsIssuerInProgram(types.NewIssuerFromString("abc")) != false {
		t.Error("Not a valid issuer")
	}

	if mi.IsIssuerInProgram(types.NewIssuerFromString("")) != false {
		t.Error("Blank is not a good issuer")
	}

	if mi.IsIssuerInProgram(types.NewIssuerFromString("Test Corporation SA")) != false {
		t.Error("Not the common name, should only respond to the Issuer")
	}

	if mi.IsIssuerInProgram(types.NewIssuerFromString(kFirstTwoLinesIssuerID)) != true {
		t.Error("Issuer should be true")
	}
}

func Test_GetCertificateForIssuer(t *testing.T) {
	mi, err := loadSampleIssuers(kFirstTwoLines)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := mi.GetCertificateForIssuer(types.NewIssuerFromString("abc"))
	if err.Error() != "Unknown issuer: abc" {
		t.Error(err)
	}
	if cert != nil {
		t.Error("Cert should have been nil")
	}

	cert, err = mi.GetCertificateForIssuer(types.NewIssuerFromString(""))
	if err == nil || err.Error() != "Unknown issuer: " {
		t.Fatal(err)
	}
	if cert != nil {
		t.Error("Cert should have been nil")
	}

	cert, err = mi.GetCertificateForIssuer(types.NewIssuerFromString(kFirstTwoLinesIssuerID))
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
	if cert == nil {
		t.Fatal("Cert should not have been nil")
	}

	if cert.Subject.String() != kFirstTwoLinesSubject {
		t.Errorf("Unexpected certificate subject %s", cert.Subject.String())
	}
}

func Test_GetSubjectForIssuer(t *testing.T) {
	mi, err := loadSampleIssuers(kFirstTwoLines)
	if err != nil {
		t.Fatal(err)
	}

	subject, err := mi.GetSubjectForIssuer(types.NewIssuerFromString("abc"))
	if err.Error() != "Unknown issuer: abc" {
		t.Error(err)
	}
	if subject != "" {
		t.Error("Subject should have been blank")
	}

	subject, err = mi.GetSubjectForIssuer(types.NewIssuerFromString(""))
	if err == nil || err.Error() != "Unknown issuer: " {
		t.Fatal(err)
	}
	if subject != "" {
		t.Error("Subject should have been blank")
	}

	subject, err = mi.GetSubjectForIssuer(types.NewIssuerFromString(kFirstTwoLinesIssuerID))
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
	if subject != kFirstTwoLinesSubject {
		t.Error("Unexpected certificate subject")
	}
}

func Test_SaveIssuersList(t *testing.T) {
	mi, err := loadSampleIssuers(kFirstTwoLines)
	if err != nil {
		t.Fatal(err)
	}

	tmpfile, err := ioutil.TempFile("", "Test_SaveIssuersList")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	err = mi.SaveIssuersList(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}

	bytes, err := ioutil.ReadFile(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}

	list := make([]EnrolledIssuer, 0)
	err = json.Unmarshal(bytes, &list)
	if err != nil {
		t.Fatal(err)
	}

	if len(list) != 1 {
		t.Errorf("Unexpected issuers list length: %+v", list)
	}
}

func Test_SaveLoadIssuersList(t *testing.T) {
	enrolledCert := makeCert(t, "CN=Enrolled Issuer", "2001-01-01",
		new(big.Int).SetInt64(0))
	enrolledIssuer := types.NewIssuer(enrolledCert)

	notEnrolledCert := makeCert(t, "CN=Not Enrolled Issuer", "2001-12-01",
		new(big.Int).SetInt64(255))
	notEnrolledIssuer := types.NewIssuer(notEnrolledCert)

	mi := NewMozillaIssuers()
	mi.InsertIssuer(enrolledCert, nil, false)

	if !mi.IsIssuerInProgram(enrolledIssuer) {
		t.Error("enrolledIssuer should be in program")
	}
	if mi.IsIssuerInProgram(notEnrolledIssuer) {
		t.Error("notEnrolledIssuer should not be in program")
	}

	tmpfile, err := ioutil.TempFile("", "Test_SaveLoadIssuersList")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	err = mi.SaveIssuersList(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}

	loadedIssuers := NewMozillaIssuers()
	if err = loadedIssuers.LoadEnrolledIssuers(tmpfile.Name()); err != nil {
		t.Fatal(err)
	}

	if !loadedIssuers.IsIssuerInProgram(enrolledIssuer) {
		t.Error("enrolledIssuer should be in program")
	}
	if loadedIssuers.IsIssuerInProgram(notEnrolledIssuer) {
		t.Error("notEnrolledIssuer should not be in program")
	}
}

func Test_NewTestIssuerFromSubjectString(t *testing.T) {
	mi := NewMozillaIssuers()
	issuer := mi.NewTestIssuerFromSubjectString("a subject")

	subject, err := mi.GetSubjectForIssuer(issuer)
	if err != nil {
		t.Error(err)
	}
	if subject != "a subject" {
		t.Errorf("Unexpected subject: %v", subject)
	}
}

func Test_LoadFromURL(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, kFirstTwoLines)
	}))
	defer ts.Close()

	tmpfile, err := ioutil.TempFile("", t.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	mi := NewMozillaIssuers()
	mi.ReportUrl = ts.URL
	mi.DiskPath = tmpfile.Name()

	err = mi.Load()
	if err != nil {
		t.Error(err)
	}

	subject, err := mi.GetSubjectForIssuer(types.NewIssuerFromString(kFirstTwoLinesIssuerID))
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
	if subject != kFirstTwoLinesSubject {
		t.Errorf("Unexpected certificate subject: %s", subject)
	}

	_, err = os.Stat(mi.DiskPath)
	if err != nil {
		t.Error(err)
	}
}

func Test_LoadFromURLToDefaultLocation(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, kFirstTwoLines)
	}))
	defer ts.Close()

	mi := NewMozillaIssuers()
	mi.ReportUrl = ts.URL
	defer os.Remove(mi.DiskPath)

	err := mi.Load()
	if err != nil {
		t.Error(err)
	}

	subject, err := mi.GetSubjectForIssuer(types.NewIssuerFromString(kFirstTwoLinesIssuerID))
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
	if subject != kFirstTwoLinesSubject {
		t.Errorf("Unexpected certificate subject: %s", subject)
	}

	_, err = os.Stat(mi.DiskPath)
	if err != nil {
		t.Error(err)
	}
}

func Test_LoadFrom404URLNoLocal(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	defer ts.Close()

	tmpfile, err := ioutil.TempFile("", t.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	mi := NewMozillaIssuers()
	mi.ReportUrl = ts.URL
	mi.DiskPath = tmpfile.Name()

	err = mi.Load()
	if err == nil {
		t.Error("Expected failure")
	}

	subject, err := mi.GetSubjectForIssuer(types.NewIssuerFromString(kFirstTwoLinesIssuerID))
	if err == nil || !strings.Contains(err.Error(), "Unknown issuer") {
		t.Errorf("Expected error, got: %s", err)
	}
	if len(subject) != 0 {
		t.Errorf("Unexpected certificate subject: %s", subject)
	}

	_, err = os.Stat(mi.DiskPath)
	if err != nil {
		t.Error(err)
	}
}

func Test_LoadFrom404URLWithLocal(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	defer ts.Close()

	tmpfile, err := ioutil.TempFile("", t.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	err = ioutil.WriteFile(tmpfile.Name(), []byte(kFirstTwoLines), 0644)
	if err != nil {
		t.Fatal(err)
	}

	mi := NewMozillaIssuers()
	mi.ReportUrl = ts.URL
	mi.DiskPath = tmpfile.Name()

	err = mi.Load()
	if err != nil {
		t.Errorf("Expected success with local file, got %s", err)
	}

	subject, err := mi.GetSubjectForIssuer(types.NewIssuerFromString(kFirstTwoLinesIssuerID))
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
	if subject != kFirstTwoLinesSubject {
		t.Errorf("Unexpected certificate subject: %s", subject)
	}

	_, err = os.Stat(mi.DiskPath)
	if err != nil {
		t.Error(err)
	}
}

func Test_LoadInvalidWithLocal(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, kFirstTwoLinesMalformed)
	}))
	defer ts.Close()

	tmpfile, err := ioutil.TempFile("", t.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	err = ioutil.WriteFile(tmpfile.Name(), []byte(kFirstTwoLines), 0644)
	if err != nil {
		t.Fatal(err)
	}

	mi := NewMozillaIssuers()
	mi.ReportUrl = ts.URL
	mi.DiskPath = tmpfile.Name()

	err = mi.Load()
	if err != nil {
		t.Errorf("Expected success with local file, got %s", err)
	}

	subject, err := mi.GetSubjectForIssuer(types.NewIssuerFromString(kFirstTwoLinesIssuerID))
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
	if subject != kFirstTwoLinesSubject {
		t.Errorf("Unexpected certificate subject: %s", subject)
	}

	_, err = os.Stat(mi.DiskPath)
	if err != nil {
		t.Error(err)
	}
}

func Test_LoadInvalidWithNoLocal(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, kFirstTwoLinesMalformed)
	}))
	defer ts.Close()

	tmpfile, err := ioutil.TempFile("", t.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	mi := NewMozillaIssuers()
	mi.ReportUrl = ts.URL
	mi.DiskPath = tmpfile.Name()

	err = mi.Load()
	if err == nil {
		t.Error("Expected failure")
	}
}

func Test_PartitionedCRLFormat(t *testing.T) {
	mi, err := loadSampleIssuers(kFirstTwoLines + "")
	if err != nil {
		t.Fatal("Should handle missing list")
	}

	mi, err = loadSampleIssuers(kFirstTwoLines + "[]")
	if err != nil || len(mi.CrlMap[kFirstTwoLinesIssuerID]) != 0 {
		t.Fatal("Should handle unquoted empty list")
	}

	mi, err = loadSampleIssuers(kFirstTwoLines + "\"[]\"")
	if err != nil || len(mi.CrlMap[kFirstTwoLinesIssuerID]) != 0 {
		t.Fatal("Should handle quoted empty list")
	}

	mi, err = loadSampleIssuers(kFirstTwoLines + "\"[]\"")
	if err != nil || len(mi.CrlMap[kFirstTwoLinesIssuerID]) != 0 {
		t.Fatal("Should handle quoted empty list")
	}

	mi, err = loadSampleIssuers(kFirstTwoLines + "\"[http://example.org]\"")
	if err != nil || len(mi.CrlMap[kFirstTwoLinesIssuerID]) != 1 {
		t.Fatal("Should handle length 1 list")
	}

	mi, err = loadSampleIssuers(kFirstTwoLines + "\"[http://example.org,]\"")
	if err != nil || len(mi.CrlMap[kFirstTwoLinesIssuerID]) != 1 {
		t.Fatalf("Should handle trailing comma")
	}

	mi, err = loadSampleIssuers(kFirstTwoLines + "\"[http://example.org,   http://example.com]\"")
	if err != nil || len(mi.CrlMap[kFirstTwoLinesIssuerID]) != 2 {
		t.Fatal("Should handle length 2 list")
	}

	mi, err = loadSampleIssuers(kFirstTwoLines + "\"\n[http://example.org,\nhttp://example.com\n,]\"")
	if err != nil || len(mi.CrlMap[kFirstTwoLinesIssuerID]) != 2 {
		t.Fatalf("Should handle new lines")
	}

	mi, err = loadSampleIssuers(kFirstTwoLines + `"[
	http://example.org/crl0,
	http://example.org/crl1,
	http://example.org/crl2,
	http://example.org/crl3,
	http://example.org/crl4,
	http://example.org/crl5,
	http://example.org/crl6,
	http://example.org/crl7,
	http://example.org/crl8,
	http://example.org/crl9
	]"`)
	if err != nil || len(mi.CrlMap[kFirstTwoLinesIssuerID]) != 10 {
		t.Fatal("Should handle long list")
	}

	mi, err = loadSampleIssuers(kFirstTwoLines + "\"[ldap://example.org]\"")
	if err != nil || len(mi.CrlMap[kFirstTwoLinesIssuerID]) != 0 {
		t.Fatalf("Should ignore CRL with unknown URL scheme")
	}

	mi, err = loadSampleIssuers(kFirstTwoLines + "\"[https://example.org]\"")
	if err != nil || len(mi.CrlMap[kFirstTwoLinesIssuerID]) != 1 {
		t.Fatalf("Should handle https scheme")
	}

	mi, err = loadSampleIssuers(kFirstTwoLines + "\"[https://example.org\\crl]\"")
	if err != nil || len(mi.CrlMap[kFirstTwoLinesIssuerID]) != 0 {
		t.Fatalf("Should ignored malformed url")
	}

}
