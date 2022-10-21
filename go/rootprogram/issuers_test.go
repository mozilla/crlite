package rootprogram

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
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
	// curl https://ccadb-public.secure.force.com/mozilla/MozillaIntermediateCertsCSVReport -s | csvtool head 2 -
	kFirstTwoLines = `Subject,Issuer,SHA256,Full CRL Issued By This CA,PEM,JSON Array of Partitioned CRLs
CN=3CX CA RSA R1; O=3CX; C=CY,CN=SSL.com SSL Enterprise Intermediate CA RSA R1; O=SSL Corp; C=US,4E93BCADD5D4E95331AE362DF9C6066CCA7F942A8FDE4D3EE011DE34074F5840,http://crls.ssl.com/3CX-TLS-I-RSA-R1.crl,"-----BEGIN CERTIFICATE-----
MIIGwDCCBKigAwIBAgIQY1mr5Pm6UFZUALZmGlylzzANBgkqhkiG9w0BAQsFADB6M
QswCQYDVQQGEwJVUzEOMAwGA1UECAwFVGV4YXMxEDAOBgNVBAcMB0hvdXN0b24xE
TAPBgNVBAoMCFNTTCBDb3JwMTYwNAYDVQQDDC1TU0wuY29tIFNTTCBFbnRlcnBya
XNlIEludGVybWVkaWF0ZSBDQSBSU0EgUjEwHhcNMjIwMTEyMTc0NDI3WhcNMzIwM
TEwMTc0NDI2WjAzMQswCQYDVQQGEwJDWTEMMAoGA1UECgwDM0NYMRYwFAYDVQQDD
A0zQ1ggQ0EgUlNBIFIxMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAx
sN5yZm/oVj1TzgLqumLxFElpxLEhxYcOSDNnqN13GmCYX/4Mmc6liTCJiNyV2sbV
TFz5+GsQuAtRvVyCyk1OhtjqpgpdSwbHnecrsBl1rifDAW0Xi0TQQKF8aVHwWKwI
3y00xQWyb4advoNy6n6f6s3HAXTc4FZ+5Bg7Kkk3KFvPouHXkB3Rdw+Q3qRqbxns
N+22oyjaNQ7GnLau9gJPJT2Qzeuu2dv3FxTl6nMO9AlhuzlHZ7J+gMo/WfkeygQ9
MBmq4+NnaaSyvl8HRLODhg1y+A7ZLItCztipdkLh3XmUgeWIfCbPbXLySeIEsJ/z
V+pPuFz0yAxvDbifpF7kw4PbHFxfwrtgS7BPFI+LtbHsQwYBfgtJJwbI42wLino5
MLdpMXa2riNwdXJUKP3DdRBaUxFrh8cXvjSQtnnLDk6z9e4/8/Mpo6E0DtNblP9c
eh8/SCguGIT8ceAsfTcKH86cqlJ1wdijEJt1+lCAyfDAofhbavtjG9vXGn/HMbn8
vx2aoB54qJnBSz/4i63bYM6FHX2xW6g2cHAN6750GT4fBihu3Ha4lTDL3A1H/NiK
BXSydrz6kib3Zl+EY2qS6vJM4V2+3m9OdH0HmvRs29FRsHMdDsAPvg1H6v9s5iYw
LyJw3GZCdTJe1aWT38vbsgvoHv0PddrAEQnI93D4BcCAwEAAaOCAYcwggGDMBIGA
1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0jBBgwFoAU0D3qopgHXUSFzwP7yr80Cp8Qx
GgwYwYIKwYBBQUHAQEEVzBVMFMGCCsGAQUFBzAChkdodHRwOi8vY2VydC5zc2wuY
29tL1NTTC5jb20tRW50ZXJwcmlzZS1JbnRlcm1lZGlhdGUtU1NMLVJTQS00MDk2L
VIxLmNlcjA/BgNVHSAEODA2MDQGBFUdIAAwLDAqBggrBgEFBQcCARYeaHR0cHM6L
y93d3cuc3NsLmNvbS9yZXBvc2l0b3J5MB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrB
gEFBQcDATBYBgNVHR8EUTBPME2gS6BJhkdodHRwOi8vY3Jscy5zc2wuY29tL1NTT
C5jb20tRW50ZXJwcmlzZS1JbnRlcm1lZGlhdGUtU1NMLVJTQS00MDk2LVIxLmNyb
DAdBgNVHQ4EFgQUt41doon0xyPta92Z4xFgOx6zOS0wDgYDVR0PAQH/BAQDAgGGM
A0GCSqGSIb3DQEBCwUAA4ICAQBJEIxHvZ4pWomrrCtLguHm4qkQTDkSxUuKswuC3
4fqrZl8D4Ue5KcTpPZK4nvHYcCnw8hq6PfhywIn5XPlfyjE99TxeRHf2WOoymFMU
WaSkB2tlD+cp7IcwVAopnF+xr4iFatPdCjFbKkPN4PkM9QVNoIiZhPKR/s3P7xLw
WsmY0P+rB/dcN26/8GEjIDHNuLUQqjLHsM0ZPWrDIa8W4xvNRUS364H/dByAu16I
dvQRfeXA+cIhVbWaeqvAjkHr3VuXzqwxbIIkQ3dYEH87Y6Z2DcPIXbTFq1e2UcBF
QXIUrTbSaDKwW+SNbitpl6QcY1raV6p6CeF0uToH1mOUGswW8EKc2P8GH/jZLVuE
CZwdrnGICvjFYwrhHOzTWFRY6ZA8Str4pTvpRUMGnsFY/+k3EnliUQoZmTrcKrzo
T55m0ZEhWohQwFCR+E/qDxvSjSIYJFDGyP+CMDjE05msxVKNwPsT82RG9xnfsyTp
KRzRXgUY7qH8+ZMbhQ5Y1/Z2ruG62DW+hFni1rJGfiQ+LFdXxF41vPzChWG1RT0U
0W+sY1OEEikx6oq+3fiXdN2XulRljW0buHucUyc134KF9pawf0cfhTKSYNH22Tvq
MOUHtflPzjKxsuOAZ5O8ZDBSHr1rCC2GDUsltyq+XHdnrdSTD5t96YuZYQ5x5/a/
7eAIg==
-----END CERTIFICATE-----",`

	kFirstTwoLinesIssuerID = "bekp6gfql9A5khD9QJvDEc0869PoPQ1WjjhIU0GCZQI="

	kFirstTwoLinesSubject = "CN=3CX CA RSA R1,O=3CX,C=CY"

	kFirstTwoLinesNoPem = `"CA Owner","Parent Name","Certificate Name","Certificate Issuer Common Name","Certificate Issuer Organization","Certificate Issuer Organizational Unit","Certificate Subject Common Name","Certificate Subject Organization","Certificate Serial Number","SHA-1 Fingerprint","SHA-256 Fingerprint","Subject + SPKI SHA256","Technically Constrained","Valid From [GMT]","Valid To [GMT]","CRL URL(s)","Public Key Algorithm","Signature Hash Algorithm","Key Usage","Extended Key Usage","CP/CPS Same As Parent","Certificate Policy (CP)","Certification Practice Statement (CPS)","Audits Same As Parent","Standard Audit","BR Audit","Auditor","Standard Audit Statement Dt","Management Assertions By","Comments","PEM"
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

func makeCert(t *testing.T, issuerDN string, expDate string, serial *big.Int) (*newx509.Certificate, string) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Error(err)
		return nil, ""
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
		return nil, ""
	}

	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}

	obj, err := newx509.ParseCertificate(certBytes)
	if err != nil {
		t.Error(err)
		return nil, ""
	}

	return obj, string(pem.EncodeToMemory(pemBlock))
}

func Test_NewMozillaIssuersInvalid(t *testing.T) {
	missingPem := `header a, header b
data a, data b`

	_, err := loadSampleIssuers(missingPem)

	if err == nil || err.Error() != "Not a valid PEM at line 2" {
		t.Error(err)
	}

	emptyPem := `issuer, PEM Info
Bob, blank`

	_, err = loadSampleIssuers(emptyPem)

	if err == nil || err.Error() != "Not a valid PEM at line 2" {
		t.Error(err)
	}
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
	enrolledCert, enrolledCertPem := makeCert(t, "CN=Enrolled Issuer", "2001-01-01",
		new(big.Int).SetInt64(0))
	enrolledIssuer := types.NewIssuer(enrolledCert)

	notEnrolledCert, notEnrolledCertPem := makeCert(t, "CN=Not Enrolled Issuer", "2001-12-01",
		new(big.Int).SetInt64(255))
	notEnrolledIssuer := types.NewIssuer(notEnrolledCert)

	mi := NewMozillaIssuers()
	mi.InsertIssuerFromCertAndPem(enrolledCert, enrolledCertPem, nil)
	mi.InsertIssuerFromCertAndPem(notEnrolledCert, notEnrolledCertPem, nil)
	mi.Enroll(enrolledIssuer)

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
	if !loadedIssuers.IsIssuerInProgram(notEnrolledIssuer) {
		t.Error("notEnrolledIssuer should be in program")
	}
	if !loadedIssuers.IsIssuerEnrolled(enrolledIssuer) {
		t.Error("enrolledIssuer should be enrolled")
	}
	if loadedIssuers.IsIssuerEnrolled(notEnrolledIssuer) {
		t.Error("notEnrolledIssuer should not be enrolled")
	}
}

func Test_IsIssuerEnrolled(t *testing.T) {
	cert, certPem := makeCert(t, "CN=Issuer", "2001-01-01",
		new(big.Int).SetInt64(0))
	issuer := types.NewIssuer(cert)

	mi := NewMozillaIssuers()
	mi.InsertIssuerFromCertAndPem(cert, certPem, nil)

	if mi.IsIssuerEnrolled(issuer) {
		t.Error("Should not yet be enrolled")
	}

	mi.Enroll(issuer)

	if !mi.IsIssuerEnrolled(issuer) {
		t.Error("Should now be enrolled")
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
		fmt.Fprintln(w, kFirstTwoLinesNoPem)
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
		fmt.Fprintln(w, kFirstTwoLinesNoPem)
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
	// The sample file in kFirstTwoLines has a full crl defined, so all the
	// counts below are 1 more than the number of partitioned crls.
	mi, err := loadSampleIssuers(kFirstTwoLines + "")
	if err != nil {
		t.Fatal("Should handle missing list")
	}

	mi, err = loadSampleIssuers(kFirstTwoLines + "[]")
	if err != nil || len(mi.CrlMap[kFirstTwoLinesIssuerID]) != 1 {
		t.Fatal("Should handle unquoted empty list")
	}

	mi, err = loadSampleIssuers(kFirstTwoLines + "\"[]\"")
	if err != nil || len(mi.CrlMap[kFirstTwoLinesIssuerID]) != 1 {
		t.Fatal("Should handle quoted empty list")
	}

	mi, err = loadSampleIssuers(kFirstTwoLines + "\"[]\"")
	if err != nil || len(mi.CrlMap[kFirstTwoLinesIssuerID]) != 1 {
		t.Fatal("Should handle quoted empty list")
	}

	mi, err = loadSampleIssuers(kFirstTwoLines + "\"[http://example.org]\"")
	if err != nil || len(mi.CrlMap[kFirstTwoLinesIssuerID]) != 2 {
		t.Fatal("Should handle length 1 list")
	}

	mi, err = loadSampleIssuers(kFirstTwoLines + "\"[http://example.org,]\"")
	if err != nil || len(mi.CrlMap[kFirstTwoLinesIssuerID]) != 2 {
		t.Fatalf("Should handle trailing comma")
	}

	mi, err = loadSampleIssuers(kFirstTwoLines + "\"[http://example.org,   http://example.com]\"")
	if err != nil || len(mi.CrlMap[kFirstTwoLinesIssuerID]) != 3 {
		t.Fatal("Should handle length 2 list")
	}

	mi, err = loadSampleIssuers(kFirstTwoLines + "\"\n[http://example.org,\nhttp://example.com\n,]\"")
	if err != nil || len(mi.CrlMap[kFirstTwoLinesIssuerID]) != 3 {
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
	if err != nil || len(mi.CrlMap[kFirstTwoLinesIssuerID]) != 11 {
		t.Fatal("Should handle long list")
	}

	mi, err = loadSampleIssuers(kFirstTwoLines + "\"[ldap://example.org]\"")
	if err != nil || len(mi.CrlMap[kFirstTwoLinesIssuerID]) != 1 {
		t.Fatalf("Should ignore CRL with unknown URL scheme")
	}

	mi, err = loadSampleIssuers(kFirstTwoLines + "\"[https://example.org]\"")
	if err != nil || len(mi.CrlMap[kFirstTwoLinesIssuerID]) != 2 {
		t.Fatalf("Should handle https scheme")
	}

	mi, err = loadSampleIssuers(kFirstTwoLines + "\"[https://example.org\\crl]\"")
	if err != nil || len(mi.CrlMap[kFirstTwoLinesIssuerID]) != 1 {
		t.Fatalf("Should ignored malformed url")
	}

}

func Test_NormalizePem(t *testing.T) {
	reference := `-----BEGIN CERTIFICATE-----
MIICxjCCAk2gAwIBAgIRALO93/inhFu86QOgQTWzSkUwCgYIKoZIzj0EAwMwTzEL
MAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2VhcmNo
IEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDIwHhcNMjAwOTA0MDAwMDAwWhcN
MjUwOTE1MTYwMDAwWjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3MgRW5j
cnlwdDELMAkGA1UEAxMCRTEwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQkXC2iKv0c
S6Zdl3MnMayyoGli72XoprDwrEuf/xwLcA/TmC9N/A8AmzfwdAVXMpcuBe8qQyWj
+240JxP2T35p0wKZXuskR5LBJJvmsSGPwSSB/GjMH2m6WPUZIvd0xhajggEIMIIB
BDAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMB
MBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFFrz7Sv8NsI3eblSMOpUb89V
yy6sMB8GA1UdIwQYMBaAFHxClq7eS0g7+pL4nozPbYupcjeVMDIGCCsGAQUFBwEB
BCYwJDAiBggrBgEFBQcwAoYWaHR0cDovL3gyLmkubGVuY3Iub3JnLzAnBgNVHR8E
IDAeMBygGqAYhhZodHRwOi8veDIuYy5sZW5jci5vcmcvMCIGA1UdIAQbMBkwCAYG
Z4EMAQIBMA0GCysGAQQBgt8TAQEBMAoGCCqGSM49BAMDA2cAMGQCMHt01VITjWH+
Dbo/AwCd89eYhNlXLr3pD5xcSAQh8suzYHKOl9YST8pE9kLJ03uGqQIwWrGxtO3q
YJkgsTgDyj2gJrjubi1K9sZmHzOa25JK1fUpE8ZwYii6I4zPPS/Lgul/
-----END CERTIFICATE-----`

	altEncoding := `
-----BEGIN CERTIFICATE-----
MIICxjCCAk2gAwIBAgIRA
LO93/inhFu86QOgQTWzSkUwCgYIKoZIzj0EAwMwTzELMAkGA1UEBhMCVVMxKTAnB
gNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2VhcmNo
IEdyb3VwMRUwEwY
DVQQDEwxJU1JHIFJvb3QgWDIwHhcNMjAwOTA0MDAwMDAwWhcNMjUwOTE1M
TYwMDAwWjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3MgRW5j
cnlwdDELMAkGA1UEAxMCRTEwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQkXC2iKv0c
S6Zdl3MnMayyoGli72XoprDwrEuf/xwLcA/TmC9N/A8AmzfwdAVXMpcuBe8qQyWj
+240JxP2T35p0wKZXuskR5LBJJvmsSGPwSSB/GjMH2m6WPUZIvd
0xhajggEIMIIB
BDAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMB
MBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFFrz7Sv8NsI3eblSMOpUb89V
yy6sMB8GA1UdIwQYMBaAFHxClq7eS0g7+pL4nozPbYupcjeVMDIGCCsGAQUFBwEB
BCYwJDAiBggrBgEFBQcwAoYWaHR0cDovL3gyLmkubGVuY3Iub3JnLzAnBgNVHR8E
IDAeMBygGqAYhhZodHRwOi8veDIuYy5sZW5jci5vcmcvMCIGA1UdIAQbMBkwCAYG
Z4EMAQIBMA0GCysGAQQBgt8TAQEBMAoGCCqGSM49BAMDA2cAMGQCMHt01VITjWH+
Dbo/AwCd89eYhNlXLr3pD5xcSAQh8suzYHKOl9YST8pE9kLJ03uGqQIwWrGxtO3q
YJkgsTgDyj2gJrjubi1K9sZmHzOa25JK1fUpE8ZwYii6I4zPPS/Lgul/
-----END CERTIFICATE-----
`

	if normalizePem(altEncoding) != normalizePem(normalizePem(altEncoding)) {
		t.Fatalf("PEM normalization should be idempotent")
	}

	if reference != normalizePem(altEncoding) {
		t.Fatalf("PEM normalization should construct reference PEM")
	}

	if reference != normalizePem(altEncoding+"trailing data") {
		t.Fatalf("PEM normalization should ignore trailing data")
	}
}
