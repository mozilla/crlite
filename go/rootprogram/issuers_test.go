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
)

func Test_NewMozillaIssuers(t *testing.T) {
	content := []byte(kFirstTwoLines)

	tmpfile, err := ioutil.TempFile("", "Test_NewMozillaIssuers")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	err = ioutil.WriteFile(tmpfile.Name(), content, 0644)
	if err != nil {
		t.Fatal(err)
	}

	mi := NewMozillaIssuers()
	err = mi.LoadFromDisk(tmpfile.Name())
	if err != nil {
		t.Error(err)
	}
}

func Test_NewMozillaIssuersInvalid(t *testing.T) {
	content := []byte(`header a, header b
data a, data b`)

	tmpfile, err := ioutil.TempFile("", "Test_NewMozillaIssuersInvalid")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	err = ioutil.WriteFile(tmpfile.Name(), content, 0644)
	if err != nil {
		t.Fatal(err)
	}

	mi := NewMozillaIssuers()
	err = mi.LoadFromDisk(tmpfile.Name())
	if err.Error() != "Not a valid PEM at line 2" {
		t.Error(err)
	}
}
