package storage

import (
	"io/ioutil"
	"net/url"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/mozilla/crlite/go"
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

	kIssuer1          = "8Rw90Ej3Ttt8RRkrg-WYDS9n7IS03bk5bjP_UXPtaY8="
	kIssuer2          = "ZkWBotC4nL-Ba_kXaVPx7TpoRSF9uwxEAuufz67J7sQ="
	kDate1            = "2099-12-31"
	kDate2            = "2100-01-01"
	kExpirationFormat = "2006-01-02"
)

func getTestHarness(t *testing.T) (*MockRemoteCache, CertDatabase) {
	tmpDir, err := ioutil.TempDir("", t.Name())
	if err != nil {
		t.Fatalf("Can't create temp dir: %s", err.Error())
	}
	mockCache := NewMockRemoteCache()
	certDB, err := NewCertDatabase(mockCache, tmpDir)
	if err != nil {
		t.Fatalf("Can't find DB: %s", err.Error())
	}
	return mockCache, certDB
}

func cacheSerial(t *testing.T, db CertDatabase, expDateStr string, issuerStr string, serialStr string) {
	issuer := types.NewIssuerFromString(issuerStr)
	expDate, err := types.NewExpDate(expDateStr)
	if err != nil {
		t.Error(err)
	}
	serial := types.NewSerialFromHex(serialStr)

	kc := db.GetSerialCacheAccessor(expDate, issuer)
	_, err = kc.Insert(serial)
	if err != nil {
		t.Error(err)
	}
}

func isCached(t *testing.T, db CertDatabase, expDateStr string, issuerStr string, serialStr string) bool {
	issuer := types.NewIssuerFromString(issuerStr)
	expDate, err := types.NewExpDate(expDateStr)
	if err != nil {
		t.Error(err)
	}
	serial := types.NewSerialFromHex(serialStr)

	kc := db.GetSerialCacheAccessor(expDate, issuer)
	cached, err := kc.Contains(serial)
	if err != nil {
		t.Error(err)
	}

	return cached
}

func expectCached(t *testing.T, db CertDatabase, expDateStr string, issuerStr string, serialStr string, expected bool) {
	if expected != isCached(t, db, expDateStr, issuerStr, serialStr) {
		t.Errorf("Expected cache bucket %s::%s to contain serial %s", expDateStr, issuerStr, serialStr)
	}
}

func expectCountStored(t *testing.T, db CertDatabase, expDateStr string, issuerStr string, serialStr string, expected uint64) {
	issuer := types.NewIssuerFromString(issuerStr)
	expDate, err := types.NewExpDate(expDateStr)
	if err != nil {
		t.Error(err)
	}

	storedSerials, err := db.ReadSerialsFromStorage(expDate, issuer)
	if err != nil {
		t.Error(err)
	}

	var count uint64 = 0
	for i := 0; i < len(storedSerials); i++ {
		if storedSerials[i].String() == serialStr {
			count++
		}
	}

	if count != expected {
		t.Errorf("Expected storage bucket %s::%s to contain serial %s exactly %d times", expDateStr, issuerStr, serialStr, expected)
	}
}

func expectStored(t *testing.T, db CertDatabase, expDateStr string, issuerStr string, serialStr string, expected bool) {
	var expectedCount uint64 = 0
	if expected {
		expectedCount = 1
	}
	expectCountStored(t, db, expDateStr, issuerStr, serialStr, expectedCount)
}

func expectCacheEmpty(t *testing.T, db CertDatabase) {
	l, err := db.GetIssuerAndDatesFromCache()
	if err != nil {
		t.Error(err)
	}
	if len(l) != 0 {
		t.Error("Cache should be empty")
	}
}

func expectStorageEmpty(t *testing.T, db CertDatabase) {
	l, err := db.GetIssuerAndDatesFromStorage()
	if err != nil {
		t.Error(err)
	}
	if len(l) != 0 {
		t.Error("Storage should be empty")
	}
}

func expectEqualIssuerDateLists(t *testing.T, list1 []types.IssuerDate, list2 []types.IssuerDate) {
	strings1 := make([]string, 0)
	strings2 := make([]string, 0)
	for i := 0; i < len(list1); i++ {
		for j := 0; j < len(list1[i].ExpDates); j++ {
			strings1 = append(strings1, list1[i].ExpDates[j].ID()+"::"+list1[i].Issuer.ID())
		}
	}
	for i := 0; i < len(list2); i++ {
		for j := 0; j < len(list2[i].ExpDates); j++ {
			strings2 = append(strings2, list2[i].ExpDates[j].ID()+"::"+list2[i].Issuer.ID())
		}
	}
	sort.Strings(strings1)
	sort.Strings(strings2)
	if len(strings1) != len(strings2) {
		t.Error("Lists are not the same length")
	}
	for i := 0; i < len(strings1); i++ {
		if strings1[i] != strings2[i] {
			t.Errorf("Lists differ at index %d", i)
		}
	}
}

func mkExp(s string) types.ExpDate {
	d, err := types.NewExpDate(s)
	if err != nil {
		panic(err)
	}
	return d
}

func test_LogState(t *testing.T, cache RemoteCache, certDB CertDatabase) {
	unknownUrl, err := url.Parse("gopher://go.pher")
	if err != nil {
		t.Fatalf("URL parse failure")
	}
	log, err := certDB.GetLogState(unknownUrl)
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
	log, err = certDB.GetLogState(normalUrl)
	if err != nil {
		t.Errorf("Should not error: %v", err)
	}
	if log.ShortURL != "log.ct/2019" {
		t.Errorf("Unexpected ShortURL %s", log.ShortURL)
	}
	if log.MaxEntry != 0 || log.MaxTimestamp != 0 {
		t.Errorf("Expected a blank log  %s", log.String())
	}

	log.MaxEntry = 9
	err = certDB.SaveLogState(log)
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

	updatedLog, err := certDB.GetLogState(normalUrl)
	if err != nil {
		t.Errorf("Should not error: %v", err)
	}
	if updatedLog.ShortURL != "log.ct/2019" {
		t.Errorf("Unexpected ShortURL %s", updatedLog.ShortURL)
	}
	if updatedLog.MaxEntry != 9 || updatedLog.MaxTimestamp != 0 {
		t.Errorf("Expected the MaxEntry to be 9 %s", updatedLog.String())
	}
}

func Test_LogState(t *testing.T) {
	cache, certDB := getTestHarness(t)
	test_LogState(t, cache, certDB)
}

func Test_Cache(t *testing.T) {
	_, certDB := getTestHarness(t)

	expectCacheEmpty(t, certDB)

	expectCached(t, certDB, kDate1, kIssuer1, "01", false)
	cacheSerial(t, certDB, kDate1, kIssuer1, "01")
	expectCached(t, certDB, kDate1, kIssuer1, "01", true)

	// insert the same value again to test idempotency
	cacheSerial(t, certDB, kDate1, kIssuer1, "01")
	expectCached(t, certDB, kDate1, kIssuer1, "01", true)

	// ensure that one bin can hold multiple values
	expectCached(t, certDB, kDate1, kIssuer1, "02", false)
	cacheSerial(t, certDB, kDate1, kIssuer1, "02")
	expectCached(t, certDB, kDate1, kIssuer1, "01", true)
	expectCached(t, certDB, kDate1, kIssuer1, "02", true)

	// ensure that separate date bins can hold the same values
	expectCached(t, certDB, kDate2, kIssuer1, "01", false)
	expectCached(t, certDB, kDate2, kIssuer1, "02", false)
	cacheSerial(t, certDB, kDate2, kIssuer1, "01")
	cacheSerial(t, certDB, kDate2, kIssuer1, "02")
	expectCached(t, certDB, kDate1, kIssuer1, "01", true)
	expectCached(t, certDB, kDate1, kIssuer1, "02", true)
	expectCached(t, certDB, kDate2, kIssuer1, "01", true)
	expectCached(t, certDB, kDate2, kIssuer1, "02", true)

	// ensure that separate issuer bins can hold the same values
	expectCached(t, certDB, kDate1, kIssuer2, "01", false)
	expectCached(t, certDB, kDate1, kIssuer2, "02", false)
	cacheSerial(t, certDB, kDate1, kIssuer2, "01")
	cacheSerial(t, certDB, kDate1, kIssuer2, "02")
	expectCached(t, certDB, kDate1, kIssuer1, "01", true)
	expectCached(t, certDB, kDate1, kIssuer1, "02", true)
	expectCached(t, certDB, kDate1, kIssuer2, "01", true)
	expectCached(t, certDB, kDate1, kIssuer2, "02", true)
}

func Test_MoveCachedSerialsToStorage(t *testing.T) {
	_, certDB := getTestHarness(t)

	expectCacheEmpty(t, certDB)
	expectStorageEmpty(t, certDB)

	cacheSerial(t, certDB, kDate1, kIssuer1, "01")
	cacheSerial(t, certDB, kDate1, kIssuer1, "02")
	cacheSerial(t, certDB, kDate1, kIssuer2, "01")
	cacheSerial(t, certDB, kDate1, kIssuer2, "02")
	cacheSerial(t, certDB, kDate2, kIssuer1, "01")
	cacheSerial(t, certDB, kDate2, kIssuer1, "02")
	cacheSerial(t, certDB, kDate2, kIssuer2, "01")
	cacheSerial(t, certDB, kDate2, kIssuer2, "02")

	expectCached(t, certDB, kDate1, kIssuer1, "01", true)
	expectCached(t, certDB, kDate1, kIssuer1, "02", true)
	expectCached(t, certDB, kDate1, kIssuer2, "01", true)
	expectCached(t, certDB, kDate1, kIssuer2, "02", true)
	expectCached(t, certDB, kDate2, kIssuer1, "01", true)
	expectCached(t, certDB, kDate2, kIssuer1, "02", true)
	expectCached(t, certDB, kDate2, kIssuer2, "01", true)
	expectCached(t, certDB, kDate2, kIssuer2, "02", true)

	expectStored(t, certDB, kDate1, kIssuer1, "01", false)
	expectStored(t, certDB, kDate1, kIssuer1, "02", false)
	expectStored(t, certDB, kDate1, kIssuer2, "01", false)
	expectStored(t, certDB, kDate1, kIssuer2, "02", false)
	expectStored(t, certDB, kDate2, kIssuer1, "01", false)
	expectStored(t, certDB, kDate2, kIssuer1, "02", false)
	expectStored(t, certDB, kDate2, kIssuer2, "01", false)
	expectStored(t, certDB, kDate2, kIssuer2, "02", false)

	cachedIssuerDates, err := certDB.GetIssuerAndDatesFromCache()
	if err != nil {
		t.Errorf("Could not get issuer-dates from cache: %s", err)
	}

	err = certDB.moveCachedSerialsToStorage()
	if err != nil {
		t.Errorf("Could not move cached serials to storage: %s", err)
	}

	storedIssuerDates, err := certDB.GetIssuerAndDatesFromStorage()
	if err != nil {
		t.Errorf("Could not get issuer-dates from storage: %s", err)
	}

	expectEqualIssuerDateLists(t, cachedIssuerDates, storedIssuerDates)

	expectCached(t, certDB, kDate1, kIssuer1, "01", false)
	expectCached(t, certDB, kDate1, kIssuer1, "02", false)
	expectCached(t, certDB, kDate1, kIssuer2, "01", false)
	expectCached(t, certDB, kDate1, kIssuer2, "02", false)
	expectCached(t, certDB, kDate2, kIssuer1, "01", false)
	expectCached(t, certDB, kDate2, kIssuer1, "02", false)
	expectCached(t, certDB, kDate2, kIssuer2, "01", false)
	expectCached(t, certDB, kDate2, kIssuer2, "02", false)

	expectStored(t, certDB, kDate1, kIssuer1, "01", true)
	expectStored(t, certDB, kDate1, kIssuer1, "02", true)
	expectStored(t, certDB, kDate1, kIssuer2, "01", true)
	expectStored(t, certDB, kDate1, kIssuer2, "02", true)
	expectStored(t, certDB, kDate2, kIssuer1, "01", true)
	expectStored(t, certDB, kDate2, kIssuer1, "02", true)
	expectStored(t, certDB, kDate2, kIssuer2, "01", true)
	expectStored(t, certDB, kDate2, kIssuer2, "02", true)
}

func Test_MoveCachedSerialsToStorageIdempotent(t *testing.T) {
	_, certDB := getTestHarness(t)

	expectCacheEmpty(t, certDB)
	expectStorageEmpty(t, certDB)

	// Repeatedly cache the same serial and move it to storage
	for i := 0; i < 4; i++ {
		cacheSerial(t, certDB, kDate1, kIssuer1, "01")
		expectCached(t, certDB, kDate1, kIssuer1, "01", true)
		expectStored(t, certDB, kDate1, kIssuer1, "01", i > 0)

		certDB.moveCachedSerialsToStorage()
		expectCached(t, certDB, kDate1, kIssuer1, "01", false)
		expectStored(t, certDB, kDate1, kIssuer1, "01", true)
	}

	// Only one copy of the serial should be in storage
	expectCountStored(t, certDB, kDate1, kIssuer1, "01", 1)
}

func Test_Commit(t *testing.T) {
	cache, certDB := getTestHarness(t)

	cacheSerial(t, certDB, kDate1, kIssuer1, "01")
	cacheSerial(t, certDB, kDate2, kIssuer1, "01")

	epoch, err := cache.GetEpoch()
	if err != nil || epoch != 0 {
		t.Error("Unexpected epoch")
	}

	err = certDB.Commit("bad token")
	if err == nil {
		t.Error("Commit should require the commit lock")
	}

	token, err := cache.AcquireCommitLock()
	if err != nil || token == nil {
		t.Error("Should have acquired commit lock")
	}

	err = certDB.Commit(*token)
	if err != nil {
		t.Errorf("Commit should have succeeded %v", err)
	}

	expectStored(t, certDB, kDate1, kIssuer1, "01", true)
	expectStored(t, certDB, kDate2, kIssuer1, "01", true)

	epoch, err = cache.GetEpoch()
	if err != nil || epoch != 1 {
		t.Error("Unexpected epoch")
	}

	cacheSerial(t, certDB, kDate1, kIssuer1, "02")
	cacheSerial(t, certDB, kDate2, kIssuer1, "02")

	err = certDB.Commit(*token)
	if err != nil {
		t.Errorf("Commit should have succeeded %v", err)
	}

	expectStored(t, certDB, kDate1, kIssuer1, "01", true)
	expectStored(t, certDB, kDate1, kIssuer1, "02", true)
	expectStored(t, certDB, kDate2, kIssuer1, "01", true)
	expectStored(t, certDB, kDate2, kIssuer1, "02", true)

	epoch, err = cache.GetEpoch()
	if err != nil || epoch != 2 {
		t.Error("Unexpected epoch")
	}

	err = cache.NextEpoch()
	err = certDB.Commit(*token)
	if err == nil {
		t.Error("Should have failed with epoch error")
	}

	cache.ReleaseCommitLock(*token)
}

func Test_RemoveExpiredSerialsFromStorage(t *testing.T) {
	_, certDB := getTestHarness(t)

	before := "2222-01-01"
	now := "3333-01-01"
	after := "4444-01-01"

	expectCacheEmpty(t, certDB)
	expectStorageEmpty(t, certDB)

	cacheSerial(t, certDB, before, kIssuer1, "01")
	cacheSerial(t, certDB, after, kIssuer1, "02")

	certDB.moveCachedSerialsToStorage()

	expectStored(t, certDB, before, kIssuer1, "01", true)
	expectStored(t, certDB, after, kIssuer1, "02", true)

	expiry, err := time.Parse(kExpirationFormat, now)
	if err != nil {
		t.Error("Failed to parse expiry")
	}
	certDB.removeExpiredSerialsFromStorage(expiry)

	expectStored(t, certDB, before, kIssuer1, "01", false)
	expectStored(t, certDB, after, kIssuer1, "02", true)
}
