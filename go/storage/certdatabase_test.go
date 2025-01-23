package storage

import (
	"io/ioutil"
	"net/url"
	"os"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/mozilla/crlite/go"
)

const (
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
	certDB, err := NewCertDatabase(mockCache, tmpDir, false)
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

func expectCacheEpoch(t *testing.T, cache RemoteCache, expected uint64) {
	epoch, err := cache.GetEpoch()
	if err != nil || epoch != expected {
		t.Errorf("Expected epoch %d got %d", expected, epoch)
	}
}

func logStatesEqual(a *types.CTLogState, b *types.CTLogState) bool {
	// Ignores LastUpdateTime
	return a.LogID == b.LogID &&
		a.MMD == b.MMD &&
		a.ShortURL == b.ShortURL &&
		a.MinEntry == b.MinEntry &&
		a.MaxEntry == b.MaxEntry &&
		a.MinTimestamp == b.MinTimestamp &&
		a.MaxTimestamp == b.MaxTimestamp
}

func expectCachedLogState(t *testing.T, cache RemoteCache, logUrl string, logState *types.CTLogState) {
	cachedLogState, err := cache.LoadLogState(logUrl)
	if err != nil {
		t.Errorf("Error getting log state: %s", err)
	}
	if !logStatesEqual(cachedLogState, logState) {
		t.Errorf("Expected cached log state to equal expected log state %v %v", cachedLogState, logState)
	}
}

func expectStoredLogState(t *testing.T, certDB CertDatabase, logUrl string, logState *types.CTLogState) {
	storedLogStates, err := certDB.GetCTLogsFromStorage()
	if err != nil {
		t.Errorf("Error getting log state: %s", err)
	}
	for _, storedLogState := range storedLogStates {
		if storedLogState.ShortURL == logUrl {
			if !logStatesEqual(&storedLogState, logState) {
				t.Errorf("Expected stored log state to equal expected log state %v %v", storedLogState, logState)
			}
			return
		}
	}
	if logState != nil {
		t.Errorf("Did not find matching log state")
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

		err := certDB.moveCachedSerialsToStorage()
		if err != nil {
			t.Errorf("Failed to move cached serials to storage: %s", err)
		}
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
	if err != nil {
		t.Error("Should have incremented cache epoch")
	}

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
	cacheSerial(t, certDB, after, kIssuer2, "02")

	err := certDB.moveCachedSerialsToStorage()
	if err != nil {
		t.Errorf("Failed to move cached serials to storage: %s", err)
	}

	expectStored(t, certDB, before, kIssuer1, "01", true)
	expectStored(t, certDB, after, kIssuer2, "02", true)

	expiry, err := time.Parse(kExpirationFormat, now)
	if err != nil {
		t.Error("Failed to parse expiry")
	}
	certDB.removeExpiredSerialsFromStorage(expiry)

	expectStored(t, certDB, before, kIssuer1, "01", false)
	expectStored(t, certDB, after, kIssuer2, "02", true)

	dirs, err := os.ReadDir(certDB.serialsDir())
	if err != nil {
		t.Error("Failed to read serials dir")
	}
	if len(dirs) != 1 {
		t.Error("Expected one issuer directory")
	}
}

func Test_EnsureCacheIsConsistent(t *testing.T) {
	cache, certDB := getTestHarness(t)

	logState := types.CTLogState{
		LogID:          "szRxVrR4eNrC0aUI0PD7gVznDV4Ihwvq1xELJwoQ9qQ=",
		MMD:            86400,
		ShortURL:       "ct.example.org/v1",
		MinEntry:       0,
		MaxEntry:       0,
		MinTimestamp:   0,
		MaxTimestamp:   0,
		LastUpdateTime: time.Now(),
	}

	err := cache.StoreLogState(&logState)
	if err != nil {
		t.Error("Should have stored log state")
	}

	expectCacheEpoch(t, cache, 0)
	expectCachedLogState(t, cache, logState.ShortURL, &logState)

	token, err := cache.AcquireCommitLock()
	if err != nil || token == nil {
		t.Error("Should have acquired commit lock")
	}
	err = certDB.Commit(*token)
	if err != nil {
		t.Errorf("Commit should have succeeded %v", err)
	}
	cache.ReleaseCommitLock(*token)

	expectCacheEpoch(t, cache, 1)
	expectCachedLogState(t, cache, logState.ShortURL, &logState)
	expectStoredLogState(t, certDB, logState.ShortURL, &logState)

	// put the cache in a bad state so that the consistency check fails
	badLogState := logState
	badLogState.MinEntry = 9999
	err = cache.Restore(31415, []types.CTLogState{badLogState})
	if err != nil {
		t.Error("Should have modified cache")
	}
	expectCacheEpoch(t, cache, 31415)
	expectCachedLogState(t, cache, logState.ShortURL, &badLogState)

	err = certDB.EnsureCacheIsConsistent()
	if err != nil {
		t.Error("Should have restored cache epoch")
	}

	if logStatesEqual(&badLogState, &logState) {
		t.Error("Can't ensure that log states were restored")
	}

	expectCacheEpoch(t, cache, 1)
	expectCachedLogState(t, cache, logState.ShortURL, &logState)
}
