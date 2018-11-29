package rootprogram

import (
	"io/ioutil"
	"os"
	"testing"
)

const (
	// curl https://ccadb-public.secure.force.com/mozilla/PublicAllInterCertsIncTechConsWithPEMCSV | head -n 36 | pbcopy
	kFirstTwoLines = `"CA Owner","Parent Name","Certificate Name","Certificate Issuer Common Name","Certificate Issuer Organization","Certificate Issuer Organizational Unit","Certificate Subject Common Name","Certificate Subject Organization","Certificate Serial Number","SHA-1 Fingerprint","SHA-256 Fingerprint","Subject + SPKI SHA256","Technically Constrained","Valid From [GMT]","Valid To [GMT]","CRL URL(s)","Public Key Algorithm","Signature Hash Algorithm","Key Usage","Extended Key Usage","CP/CPS Same As Parent","Certificate Policy (CP)","Certification Practice Statement (CPS)","Audits Same As Parent","Standard Audit","BR Audit","Auditor","Standard Audit Statement Dt","Management Assertions By","Comments","PEM Info"
"AC Camerfirma, S.A.","AC Camerfirma","RACER","AC Camerfirma","AC Camerfirma SA","","RACER","AC Camerfirma SA","01","F82701F8E04770F3448C19070F9B2158B16621A0","F1712177935DBA40BDBD99C5F753319CF6293549B7284741E43916AD3BFBDD75","80C14510C26519770718D4086A713C32DBC2209FF30B2AAA36523CC310424096","false","2003 Dec 04","2023 Dec 04","http://crl.camerfirma.com/racer.crl","RSA 2047 bits","SHA1WithRSA","Digital Signature, Certificate Sign, CRL Sign","(not present)","TRUE","","","TRUE","","","","","","","'-----BEGIN CERTIFICATE-----
MIIGDzCCBPegAwIBAgIBATANBgkqhkiG9w0BAQUFADCBxjELMAkGA1UEBhMCRVMx
KzApBgkqhkiG9w0BCQEWHGFjX2NhbWVyZmlybWFAY2FtZXJmaXJtYS5jb20xEjAQ
BgNVBAUTCUE4Mjc0MzI4NzFDMEEGA1UEBxM6TWFkcmlkIChzZWUgY3VycmVudCBh
ZGRyZXNzIGF0IHd3dy5jYW1lcmZpcm1hLmNvbS9hZGRyZXNzKTEZMBcGA1UEChMQ
QUMgQ2FtZXJmaXJtYSBTQTEWMBQGA1UEAxMNQUMgQ2FtZXJmaXJtYTAeFw0wMzEy
MDQxNzI2NDFaFw0yMzEyMDQxNzI2NDFaMIG4MQswCQYDVQQGEwJFUzElMCMGCSqG
SIb3DQEJARYWY2FyYWNlckBjYW1lcmZpcm1hLmNvbTFDMEEGA1UEBxM6TWFkcmlk
IChzZWUgY3VycmVudCBhZGRyZXNzIGF0IHd3dy5jYW1lcmZpcm1hLmNvbS9hZGRy
ZXNzKTESMBAGA1UEBRMJQTgyNzQzMjg3MRkwFwYDVQQKExBBQyBDYW1lcmZpcm1h
IFNBMQ4wDAYDVQQDEwVSQUNFUjCCAR8wDQYJKoZIhvcNAQEBBQADggEMADCCAQcC
ggEAe03yy1HZxgtdg1b2NocXqtM73x6992kg9feecE3t36NAdYmy+oh6MKrT3CIQ
RiHLm+/RyyudD6o0D0LNeGrRYpcFw7zEOYX/mMGTIXKLPku7BdoCvgyx4amyBigZ
V6AjGn4+xIzQy5ljOyVlnfFfI49awkfX0+BNv5qWKpshg+WnFOW1Gd0MJXMH6uNs
u2/HdqSgsvUQ1dQNelKxz+EbTfiuw+HwgQbpf/nse4oGv0cq0pA85gdEoO+fLOwR
Z8DOfAaVYATnqfTvYexwYYcQ7NWDxCX05iVs51rbt5QrwIq/St7L/6xQd++0mlfA
JoC7TF5Casqh2uS5KSMgI9WPwwIBA6OCAhUwggIRMBIGA1UdEwEB/wQIMAYBAf8C
AQowNAYDVR0fBC0wKzApoCegJYYjaHR0cDovL2NybC5jYW1lcmZpcm1hLmNvbS9y
YWNlci5jcmwwHQYDVR0OBBYEFL68CNQuugBMgNwmZ7Sl2N3DShr5MIGoBgNVHSME
gaAwgZ2AFHDBlfpdpRa+YuikfePUZF/E4T6doYGBpH8wfTELMAkGA1UEBhMCRVUx
JzAlBgNVBAoTHkFDIENhbWVyZmlybWEgU0EgQ0lGIEE4Mjc0MzI4NzEjMCEGA1UE
CxMaaHR0cDovL3d3dy5jaGFtYmVyc2lnbi5vcmcxIDAeBgNVBAMTF0dsb2JhbCBD
aGFtYmVyc2lnbiBSb290ggECME0GCCsGAQUFBwEBBEEwPzA9BggrBgEFBQcwAoYx
aHR0cDovL3d3dy5jYW1lcmZpcm1hLmNvbS9jZXJ0cy9hY19jYW1lcmZpcm1hLmNy
dDAOBgNVHQ8BAf8EBAMCAYYwIQYDVR0RBBowGIEWY2FyYWNlckBjYW1lcmZpcm1h
LmNvbTAnBgNVHRIEIDAegRxhY19jYW1lcmZpcm1hQGNhbWVyZmlybWEuY29tMFAG
A1UdIARJMEcwRQYLKwYBBAGBhy4KCAEwNjA0BggrBgEFBQcCARYoaHR0cDovL2Nw
cy5jYW1lcmZpcm1hLmNvbS9jcHMvcmFjZXIuaHRtbDANBgkqhkiG9w0BAQUFAAOC
AQEAVPqOALDxl2F8rgu67OcqomMXR3aPIyFE4mFeKOzVpQFsRRzkls3c1ZDTGYlV
h9XnL4AIBJ/U1ukRkGuIZHIYUWiNADWd0HImPb5Hzgip0R9dNXP2SrSo4d2iB7gq
R86X1t3bjdf152PuCm/tE6slmR13VqKmjSd1sYxTNAKePu3IYDZgGLnNFd3qN2Qb
PWq69Z/1ql+7L7a15TXcBNQXsfQEOLGx5i9ZeNDVmpSHJ6swHO3Gql2n/qNuNHgb
w7+QZfZHary2ArgMCU2SmpCmpybktruKwGbelQHYC2oJavTHoLd5GeHI4GivPIE9
cxhzf8XjZXECKL54a/4o9ISBcA==
-----END CERTIFICATE-----'"
`
	kFirstTwoLinesAKI     = "vrwI1C66AEyA3CZntKXY3cNKGvk="
	kFirstTwoLinesSubject = "SERIALNUMBER=A82743287,CN=RACER,O=AC Camerfirma SA,L=Madrid (see current address at www.camerfirma.com/address),C=ES"

  kEmptySPKI = `"CA Owner","Parent Name","Certificate Name","Certificate Issuer Common Name","Certificate Issuer Organization","Certificate Issuer Organizational Unit","Certificate Subject Common Name","Certificate Subject Organization","Certificate Serial Number","SHA-1 Fingerprint","SHA-256 Fingerprint","Subject + SPKI SHA256","Technically Constrained","Valid From [GMT]","Valid To [GMT]","CRL URL(s)","Public Key Algorithm","Signature Hash Algorithm","Key Usage","Extended Key Usage","CP/CPS Same As Parent","Certificate Policy (CP)","Certification Practice Statement (CPS)","Audits Same As Parent","Standard Audit","BR Audit","Auditor","Standard Audit Statement Dt","Management Assertions By","Comments","PEM Info"
"Test Corporation","Test Corporation","test","Test Corporation","Test Corporation CA","","test","Test Corporation CA","71:8a:bd:2f:20:13:18:ea:a2:73:67:b0:3d:b5:3f:6b:24:3c:f6:f5","F82701F8E04770F3448C19070F9B2158B16621A0","F1712177935DBA40BDBD99C5F753319CF6293549B7284741E43916AD3BFBDD75","80C14510C26519770718D4086A713C32DBC2209FF30B2AAA36523CC310424096","false","2016 Nov 27","2019 Feb 05","http://crl.example.com/test.crl","RSA 2048 bits","SHA1WithRSA","Digital Signature, Certificate Sign, CRL Sign","(not present)","TRUE","","","TRUE","","","","","","","'-----BEGIN CERTIFICATE-----
MIICyTCCAbGgAwIBAgIURxOdvmKY1LMeejuRTiuHeGBhZHwwDQYJKoZIhvcNAQEL
BQAwDTELMAkGA1UEAwwCY2EwIhgPMjAxNjExMjcwMDAwMDBaGA8yMDE5MDIwNTAw
MDAwMFowDTELMAkGA1UEAwwCY2EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQC6iFGoRI4W1kH9braIBjYQPTwT2erkNUq07PVoV2wke8HHJajg2B+9sZwG
m24ahvJr4q9adWtqZHEIeqVap0WH9xzVJJwCfs1D/B5p0DggKZOrIMNJ5Nu5TMJr
bA7tFYIP8X6taRqx0wI6iypB7qdw4A8Njf1mCyuwJJKkfbmIYXmQsVeQPdI7xeC4
SB+oN9OIQ+8nFthVt2Zaqn4CkC86exCABiTMHGyXrZZhW7filhLAdTGjDJHdtMr3
/K0dJdMJ77kXDqdo4bN7LyJvaeO0ipVhHe4m1iWdq5EITjbLHCQELL8Wiy/l8Y+Z
FzG4s/5JI/pyUcQx1QOs2hgKNe2NAgMBAAGjHTAbMAwGA1UdEwQFMAMBAf8wCwYD
VR0PBAQDAgEGMA0GCSqGSIb3DQEBCwUAA4IBAQBXd3Rnz2WW+aczo/SPlYSst4Bp
hWx6S3ncLB4RznGMCTndfJCkpOdkDvDi9swIN4xO19XlUJFX5FiJ9vbjrxgz1hV9
/FsqApPRAMuA6cWMOFWtIu/qgurcCMpgcPyO6MKGR1YH1C2fpVIDIDc/ID7sIpLt
m208pK6P9J61ka0QqjQkQZ1aDulBj+6Ic5GYwyJXAWyE3OoUJPteGM12yfT/7lOC
ObxJaqJrOYQEmI2ZZQ67MjDgfvivopIFQKOJvlBJKHujDSz3ZFykwx7CwnvN74sJ
07snm4Vz6lAKESVa4H65oExOqL1kEMQQKyNmOKEAMOmHM+L4toh17ax4q2xP
-----END CERTIFICATE-----'"`
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

func Test_NewMozillaIssuersInvalid(t *testing.T) {
	missingPem := `header a, header b
data a, data b`

	_, err := loadSampleIssuers(missingPem)

	if err.Error() != "Not a valid PEM at line 2" {
		t.Error(err)
	}

	emptyPem := `issuer, PEM Info
Bob, blank`

	_, err = loadSampleIssuers(emptyPem)

	if err.Error() != "Not a valid PEM at line 2" {
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
		t.Error("Expecting one issuer")
	}

	if issuers[0] != kFirstTwoLinesAKI {
		t.Errorf("Unexpected issuer SPKI, got: [%s]", issuers[0])
	}
}


func Test_GetIssuersEmptySPKI(t *testing.T) {
	mi, err := loadSampleIssuers(kEmptySPKI)
	if err != nil {
		t.Fatal(err)
	}

	issuers := mi.GetIssuers()
	if len(issuers) != 1 {
		t.Error("Expecting one issuer")
	}

	if issuers[0] != "RZQbKdvDIkL6QOTsnXF6e3X6zUU=" {
		t.Errorf("SPKI should have been replaced with the sha1 value")
	}
}

func Test_IsIssuerInProgram(t *testing.T) {
	mi, err := loadSampleIssuers(kFirstTwoLines)
	if err != nil {
		t.Fatal(err)
	}

	if mi.IsIssuerInProgram("abc") != false {
		t.Error("Not a valid issuer")
	}

	if mi.IsIssuerInProgram("") != false {
		t.Error("Blank is not a good issuer")
	}

	if mi.IsIssuerInProgram("Test Corporation SA") != false {
		t.Error("Not the common name, should only respond to the AKI")
	}

	if mi.IsIssuerInProgram(kFirstTwoLinesAKI) != true {
		t.Error("AKI should be true")
	}
}

func Test_GetCertificateForIssuer(t *testing.T) {
	mi, err := loadSampleIssuers(kFirstTwoLines)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := mi.GetCertificateForIssuer("abc")
	if err.Error() != "Unknown issuer: abc" {
		t.Error(err)
	}
	if cert != nil {
		t.Error("Cert should have been nil")
	}

	cert, err = mi.GetCertificateForIssuer("")
	if err != nil && err.Error() != "Unknown issuer: " {
		t.Fatal(err)
	}
	if cert != nil {
		t.Error("Cert should have been nil")
	}

	cert, err = mi.GetCertificateForIssuer(kFirstTwoLinesAKI)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
	if cert == nil {
		t.Fatal("Cert should not have been nil")
	}

	if cert.Subject.String() != kFirstTwoLinesSubject {
		t.Error("Unexpected certificate subject")
	}
}

func Test_GetSubjectForIssuer(t *testing.T) {
	mi, err := loadSampleIssuers(kFirstTwoLines)
	if err != nil {
		t.Fatal(err)
	}

	subject, err := mi.GetSubjectForIssuer("abc")
	if err.Error() != "Unknown issuer: abc" {
		t.Error(err)
	}
	if subject != "" {
		t.Error("Subject should have been blank")
	}

	subject, err = mi.GetSubjectForIssuer("")
	if err != nil && err.Error() != "Unknown issuer: " {
		t.Fatal(err)
	}
	if subject != "" {
		t.Error("Subject should have been blank")
	}

	subject, err = mi.GetSubjectForIssuer(kFirstTwoLinesAKI)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
	if subject != kFirstTwoLinesSubject {
		t.Error("Unexpected certificate subject")
	}
}
