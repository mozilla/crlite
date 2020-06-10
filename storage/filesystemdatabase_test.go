package storage

import (
	"bytes"
	"context"
	"encoding/pem"
	"net/url"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/x509"
)

const (
	kEmptySPKI = `-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----`

	kRealSPKI = `-----BEGIN CERTIFICATE-----
MIIFDTCCA/WgAwIBAgIKEuOBUwAAAAAAHTANBgkqhkiG9w0BAQUFADCBijELMAkG
A1UEBhMCQ0gxEDAOBgNVBAoTB1dJU2VLZXkxJjAkBgNVBAsTHUNvcHlyaWdodCAo
YykgMjAwNSBXSVNlS2V5IFNBMRYwFAYDVQQLEw1JbnRlcm5hdGlvbmFsMSkwJwYD
VQQDEyBXSVNlS2V5IENlcnRpZnlJRCBTdGFuZGFyZCBHMSBDQTAeFw0xMjAxMjMx
NTMyMjBaFw0yMDEyMjMxMDU1MzJaMIGSMQswCQYDVQQGEwJDSDEQMA4GA1UEChMH
V0lTZUtleTEmMCQGA1UECxMdQ29weXJpZ2h0IChjKSAyMDEyIFdJU2VLZXkgU0Ex
FjAUBgNVBAsTDUludGVybmF0aW9uYWwxMTAvBgNVBAMTKFdJU2VLZXkgQ2VydGlm
eUlEIFN0YW5kYXJkIFNlcnZpY2VzIENBIDIwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDEwRJCD5mtCZwFwgKi/6mQYZYKdnw6iJd3RRUQYaJ3BQ13Mw2R
W+YAkWn7TjawcRb7wGpC/16KDaEM13d5As61egVZsXb4cgI1xLZI4ok9tlh+SHm6
SX38HCcOKg4YT43xcq1b5pcerhp5/HsI+wovic2WIuA/BVD4Tv0t46EP2avjijQP
CcRPYhaGLC6dtqfSh0/jcutPJJRG9An29KcPfx137bTkFrQnUZTR0SThkixhWpsY
iCVFCazKMHlwUDXKa0m41BI6q01lmDfz1Hfuft5r89ltThCKkTvo//a3gulz43DO
9qv5emTHISqZXOi8fRCWa05TP5Q+AK5RhjTPAgMBAAGjggFpMIIBZTASBgNVHRMB
Af8ECDAGAQH/AgEAMB0GA1UdDgQWBBS79c6uWyghS9wCtE1Nj7NK4rThkzALBgNV
HQ8EBAMCAYYwEAYJKwYBBAGCNxUBBAMCAQAwTgYDVR0gBEcwRTA7BghghXQFDgQC
ATAvMC0GCCsGAQUFBwIBFiFodHRwOi8vd3d3Lndpc2VrZXkuY29tL3JlcG9zaXRv
cnkwBgYEVR0gADAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTAfBgNVHSMEGDAW
gBT62HEyPNzq0jV+X9hk4vH/HGarbTA8BgNVHR8ENTAzMDGgL6AthitodHRwOi8v
cHVibGljLndpc2VrZXkuY29tL2NybC93Y2lkc2cxY2EuY3JsMEcGCCsGAQUFBwEB
BDswOTA3BggrBgEFBQcwAoYraHR0cDovL3B1YmxpYy53aXNla2V5LmNvbS9jcnQv
d2NpZHNnMWNhLmNydDANBgkqhkiG9w0BAQUFAAOCAQEAe0VgXnBsOf3nvyagCyzG
G67gxFooo8QrHSYhA0da9TrPh0Jln0FkEh4zN5pA+hgL353tBAYDkPhbcCwW+t50
n9R8y3VVaaSCqP2NpU+GTfd/D8OM8sGf7KGFzVh/1Cx2x7whaBZ1w1F/BDX/LEmP
4aJX0+2l+XHM7ejbZBv52hqZxHFxY2qTl0bV2WfaDh7UYkqjzkE7HW9vgLD13X5B
Daidl1Taa2zjouW/BTuwmD/8WbTSP4KJpblia+2LtzO6VJV/if7wqXZr4UA0kpTY
wKo3zx2WdFVsOLYnt/QsOZS8WsdlNR30V/040wPH+F6XNPnTnlw0UxZzt/mnWmeU
EA==
-----END CERTIFICATE-----`
)

func getTestHarness(t *testing.T) (*MockBackend, *MockRemoteCache, CertDatabase) {
	mockBackend := NewMockBackend()
	mockCache := NewMockRemoteCache()
	storageDB, err := NewFilesystemDatabase(mockBackend, mockCache)
	if err != nil {
		t.Fatalf("Can't find DB: %s", err.Error())
	}
	if storageDB == nil {
		t.Fatalf("Can't find DB")
	}
	return mockBackend, mockCache, storageDB
}

func Test_GetSpkiRealSPKI(t *testing.T) {
	b, _ := pem.Decode([]byte(kRealSPKI))

	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Error(err)
	}

	spki := getSpki(cert)
	if bytes.Equal(spki.spki, cert.SubjectKeyId) == false {
		t.Error("SPKI should be out of the certificate")
	}
}

func Test_GetSpkiSyntheticSPKI(t *testing.T) {
	b, _ := pem.Decode([]byte(kEmptySPKI))

	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Error(err)
	}

	if len(cert.SubjectKeyId) != 0 {
		t.Fatal("The empty SPKI should be length 0")
	}

	spki := getSpki(cert)

	if len(spki.spki) != 20 {
		t.Errorf("Synthetic SPKI should be 20 bytes long: %d %s", len(spki.spki), spki.ID())
	}
}

func mkExp(s string) ExpDate {
	d, err := NewExpDate(s)
	if err != nil {
		panic(err)
	}
	return d
}

func expDatesAndStringsEqual(t *testing.T, expected []string, found ExpDateList) {
	if len(expected) != len(found) {
		t.Errorf("Expected %s result %s", expected, found)
	}
	for i, val := range expected {
		if found[i].ID() != val {
			t.Errorf("Mismatch at idx=%d: expected %s got %s", i, val, found[i])
		}
	}
}

func Test_ListExpiration(t *testing.T) {
	mockBackend, _, storageDB := getTestHarness(t)

	testIssuer := NewIssuerFromString("test issuer")

	if err := mockBackend.AllocateExpDateAndIssuer(context.TODO(), mkExp("2017-11-28"), testIssuer); err != nil {
		t.Error(err)
	}
	if err := mockBackend.AllocateExpDateAndIssuer(context.TODO(), mkExp("2018-11-28"), testIssuer); err != nil {
		t.Error(err)
	}
	if err := mockBackend.AllocateExpDateAndIssuer(context.TODO(), mkExp("2019-11-28"), testIssuer); err != nil {
		t.Error(err)
	}

	var refTime time.Time
	var expDates ExpDateList
	var err error

	// All dirs valid.
	expectedDates := []string{"2017-11-28", "2018-11-28", "2019-11-28"}
	refTime, err = time.Parse(time.RFC3339, "2016-11-29T15:04:05Z")
	if err != nil {
		t.Fatalf("Couldn't parse time %+v", err)
	}
	expDates, err = storageDB.ListExpirationDates(refTime)
	sort.Sort(expDates)
	if err != nil {
		t.Fatalf("%s", err.Error())
	}

	expDatesAndStringsEqual(t, expectedDates, expDates)

	// Some dirs valid.
	expectedDates = []string{"2019-11-28"}
	refTime, err = time.Parse(time.RFC3339, "2018-11-29T15:04:05Z")
	if err != nil {
		t.Fatalf("Couldn't parse time %+v", err)
	}
	expDates, err = storageDB.ListExpirationDates(refTime)
	sort.Sort(expDates)
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	expDatesAndStringsEqual(t, expectedDates, expDates)

	// Close-in date, it's the same day as the expiration tag
	expectedDates = []string{"2019-11-28"}
	refTime, err = time.Parse(time.RFC3339, "2019-11-28T01:04:05Z")
	if err != nil {
		t.Fatalf("Couldn't parse time %+v", err)
	}
	expDates, err = storageDB.ListExpirationDates(refTime)
	sort.Sort(expDates)
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	expDatesAndStringsEqual(t, expectedDates, expDates)

	// No dirs valid
	expectedDates = []string{}
	refTime, err = time.Parse(time.RFC3339, "2020-11-29T15:04:05Z")
	if err != nil {
		t.Fatalf("Couldn't parse time %+v", err)
	}
	expDates, err = storageDB.ListExpirationDates(refTime)
	sort.Sort(expDates)
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	expDatesAndStringsEqual(t, expectedDates, expDates)

	// Some dirs valid with ref year, month, and day equal to a dir name
	expectedDates = []string{"2018-11-28", "2019-11-28"}
	refTime, err = time.Parse(time.RFC3339, "2018-11-28T23:59:59Z")
	if err != nil {
		t.Fatalf("Couldn't parse time %+v", err)
	}
	expDates, err = storageDB.ListExpirationDates(refTime)
	sort.Sort(expDates)
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	expDatesAndStringsEqual(t, expectedDates, expDates)
}

func Test_LogState(t *testing.T) {
	_, cache, storageDB := getTestHarness(t)

	unknownUrl, err := url.Parse("gopher://go.pher")
	if err != nil {
		t.Fatalf("URL parse failure")
	}
	log, err := storageDB.GetLogState(unknownUrl)
	if err != nil {
		t.Errorf("Unknown logs should be OK")
	}
	if log == nil {
		t.Fatalf("Log shouldn't be nil")
	}

	normalUrl, err := url.Parse("https://log.ct/2019")
	if err != nil {
		t.Fatalf("URL parse failure")
	}
	log, err = storageDB.GetLogState(normalUrl)
	if err != nil {
		t.Errorf("Should not error: %v", err)
	}
	if log.ShortURL != "log.ct/2019" {
		t.Errorf("Unexpected ShortURL %s", log.ShortURL)
	}
	if log.MaxEntry != 0 || !log.LastEntryTime.IsZero() {
		t.Errorf("Expected a blank log  %s", log.String())
	}

	log.MaxEntry = 9
	err = storageDB.SaveLogState(log)
	if err != nil {
		t.Errorf("Shouldn't have errored saving %v", err)
	}

	cacheObj, err := cache.LoadLogState(log.ShortURL)
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(cacheObj, log) {
		t.Errorf("Expected the cache to have the exact same log state, %+v %+v", cacheObj, log)
	}

	updatedLog, err := storageDB.GetLogState(normalUrl)
	if err != nil {
		t.Errorf("Should not error: %v", err)
	}
	if updatedLog.ShortURL != "log.ct/2019" {
		t.Errorf("Unexpected ShortURL %s", updatedLog.ShortURL)
	}
	if updatedLog.MaxEntry != 9 || !updatedLog.LastEntryTime.IsZero() {
		t.Errorf("Expected the MaxEntry to be 9 %s", updatedLog.String())
	}
}

func Test_GetIssuerAndDatesFromCache(t *testing.T) {
	_, _, storageDB := getTestHarness(t)

	l, err := storageDB.GetIssuerAndDatesFromCache()
	if err != nil {
		t.Error(err)
	}
	if len(l) != 0 {
		t.Errorf("Should have been empty with an empty DB: %v", l)
	}

	issuer := NewIssuerFromString("Honesty Issuer")

	{
		expDate, err := NewExpDate("2040-02-03-19")
		if err != nil {
			t.Error(err)
		}
		serial := NewSerialFromHex("FEEDBEEF")

		kc := storageDB.GetKnownCertificates(expDate, issuer)
		_, err = kc.WasUnknown(serial)
		if err != nil {
			t.Error(err)
		}
	}

	l2, err := storageDB.GetIssuerAndDatesFromCache()
	if err != nil {
		t.Error(err)
	}
	if len(l2) != 1 {
		t.Errorf("Should have been one issuer: %v", l2)
	}
	if len(l2[0].ExpDates) != 1 {
		t.Errorf("Should have been one expDate %v", l2[0].ExpDates)
	}

	{
		expDate, err := NewExpDate("2040-02-03")
		if err != nil {
			t.Error(err)
		}
		serial := NewSerialFromHex("BEEF")
		kc := storageDB.GetKnownCertificates(expDate, issuer)
		_, err = kc.WasUnknown(serial)
		if err != nil {
			t.Error(err)
		}
	}

	l3, err := storageDB.GetIssuerAndDatesFromCache()
	if err != nil {
		t.Error(err)
	}
	if len(l3) != 1 {
		t.Errorf("Should have been one issuer: %v", l3)
	}
	if len(l3[0].ExpDates) != 2 {
		t.Errorf("Should have been two expDates %v", l3[0].ExpDates)
	}
}
