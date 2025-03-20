package storage

import (
	"fmt"
	"math/rand"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/mozilla/crlite/go"
)

var kRedisHost = "RedisHost"

func getRedisCache(tb testing.TB) *RedisCache {
	setting, ok := os.LookupEnv(kRedisHost)
	if !ok {
		tb.Skipf("%s is not set, unable to run %s. Skipping.", kRedisHost, tb.Name())
	}
	tb.Logf("Connecting to Redis instance at %s", setting)

	rc, err := NewRedisCache(setting, time.Second)
	if err != nil {
		tb.Errorf("Couldn't construct RedisCache: %v", err)
	}
	return rc
}

func Test_RedisPoicy(t *testing.T) {
	t.Parallel()
	rc := getRedisCache(t)
	if err := rc.MemoryPolicyCorrect(); err != nil {
		t.Error(err)
	}
}

func Test_RedisInvalidHost(t *testing.T) {
	t.Parallel()
	_, err := NewRedisCache("unknown_host:999999", time.Second)
	if err == nil {
		t.Error("Should have failed to construct invalid redis cache host")
	}
}

func Test_RedisInsertion(t *testing.T) {
	t.Parallel()
	rc := getRedisCache(t)
	defer rc.client.Del("key")

	firstExists, err := rc.Exists("key")
	if err != nil {
		t.Error(err)
	}
	if firstExists == true {
		t.Error("Key shouldn't exist yet")
	}

	firstInsert, err := rc.SetInsert("key", "FADEC00DEAD00DEAF00CAFE0")
	if err != nil {
		t.Error(err)
	}
	if firstInsert == false {
		t.Errorf("Should have inserted")
	}

	secondExists, err := rc.Exists("key")
	if err != nil {
		t.Error(err)
	}
	if secondExists == false {
		t.Error("Key should now exist")
	}

	doubleInsert, err := rc.SetInsert("key", "FADEC00DEAD00DEAF00CAFE0")
	if err != nil {
		t.Error(err)
	}
	if doubleInsert == true {
		t.Errorf("Shouldn't have re-inserted")
	}

	shouldntExist, err := rc.SetContains("key", "BEAC040FBAC040")
	if err != nil {
		t.Error(err)
	}
	if shouldntExist == true {
		t.Errorf("This serial should not have been saved")
	}

	shouldExist, err := rc.SetContains("key", "FADEC00DEAD00DEAF00CAFE0")
	if err != nil {
		t.Error(err)
	}
	if shouldExist == false {
		t.Errorf("This serial should have been saved")
	}

	err = rc.SetRemove("key", []string{"FADEC00DEAD00DEAF00CAFE0"})
	if err != nil {
		t.Error(err)
	}

	shouldBeRemoved, err := rc.SetContains("key", "FADEC00DEAD00DEAF00CAFE0")
	if err != nil {
		t.Error(err)
	}
	if shouldBeRemoved == true {
		t.Errorf("This serial should have been removed")
	}
}

func Test_RedisSets(t *testing.T) {
	t.Parallel()
	rc := getRedisCache(t)
	q := "setCache"
	defer rc.client.Del(q)

	sortedSerials := make([]string, 999)

	for i := 0; i < len(sortedSerials); i++ {
		sortedSerials[i] = fmt.Sprintf("%04X", i)
	}

	randomSerials := make([]string, len(sortedSerials))
	copy(randomSerials[:], sortedSerials)

	rand.Shuffle(len(sortedSerials), func(i, j int) {
		randomSerials[i], randomSerials[j] = randomSerials[j], randomSerials[i]
	})

	for _, s := range randomSerials {
		success, err := rc.SetInsert(q, s)
		if err != nil {
			t.Error(err)
		}
		if success != true {
			t.Errorf("Failed to insert %v", s)
		}
	}

	rand.Shuffle(len(randomSerials), func(i, j int) {
		randomSerials[i], randomSerials[j] = randomSerials[j], randomSerials[i]
	})

	for _, s := range randomSerials {
		// check'em
		exists, err := rc.SetContains(q, s)
		if err != nil {
			t.Error(err)
		}
		if exists != true {
			t.Errorf("Should have existed! %s", s)
		}
	}

	list, err := rc.SetList(q)
	if err != nil {
		t.Error(err)
	}
	if len(list) != len(sortedSerials) {
		t.Errorf("Expected %d serials but got %d", len(sortedSerials), len(list))
	}

	c := make(chan string)
	go func() {
		err = rc.SetToChan(q, c)
		if err != nil {
			t.Error(err)
		}
	}()
	counter := 0
	for v := range c {
		var found bool
		for _, s := range sortedSerials {
			if s == v {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Unexpected value from chan, got %s", v)
		}
		counter++
	}
	if counter != len(sortedSerials) {
		t.Errorf("Expected %d values from the channel, got %d", len(sortedSerials),
			counter)
	}

	card, err := rc.SetCardinality(q)
	if err != nil {
		t.Error(err)
	}
	if card != counter {
		t.Errorf("Expected exact SetCardinality match, got ")
	}
}

func Test_RedisExpiration(t *testing.T) {
	t.Parallel()
	rc := getRedisCache(t)
	defer rc.client.Del("expTest")

	success, err := rc.SetInsert("expTest", "a")
	if !success || err != nil {
		t.Errorf("Should have inserted: %v", err)
	}

	if exists, err := rc.Exists("expTest"); exists == false || err != nil {
		t.Errorf("Should exist: %v %v", exists, err)
	}

	anHourAgo := time.Now().Add(time.Hour * -1)
	if err := rc.ExpireAt("expTest", anHourAgo); err != nil {
		t.Error(err)
	}

	if exists, err := rc.Exists("expTest"); exists == true || err != nil {
		t.Errorf("Should not exist anymore: %v %v", exists, err)
	}
}

func expectNilLogState(t *testing.T, rc *RedisCache, url string) {
	obj, err := rc.LoadLogState(url)
	if obj != nil {
		t.Errorf("Expected a nil state, obtained %+v for %s", obj, url)
	}
	if err == nil {
		t.Error("Expected an error")
	}
}

func Test_RedisLogState(t *testing.T) {
	t.Parallel()
	rc := getRedisCache(t)
	rc.client.Del("log::short_url/location")
	defer rc.client.Del("log::short_url/location")

	log := &types.CTLogState{
		ShortURL:     "short_url/location",
		MaxEntry:     123456789,
		MaxTimestamp: uint64(time.Now().Unix()),
	}

	expectNilLogState(t, rc, log.ShortURL)

	err := rc.StoreLogState(log)
	if err != nil {
		t.Error(err)
	}

	obj, err := rc.LoadLogState(log.ShortURL)
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(log, obj) {
		t.Errorf("expected identical log objects: %+v %+v", log, obj)
	}

	expectNilLogState(t, rc, "")
	expectNilLogState(t, rc, fmt.Sprintf("%s/a", log.ShortURL))
}

func expectLocked(t *testing.T, rc *RedisCache, aToken *string, aExpected bool) {
	locked, err := rc.HasCommitLock(*aToken)
	if err != nil {
		t.Errorf("Error in HasCommitLock: %v", err)
	}
	if aExpected != locked {
		t.Errorf("Locking error: locked (%t), expected (%t)", locked, aExpected)
	}
}

func Test_RedisCommitLock(t *testing.T) {
	rc := getRedisCache(t)

	invalidToken := "invalid token"
	// HasCommitLock should return false for invalid tokens
	expectLocked(t, rc, &invalidToken, false)

	// We should be able to acquire the lock
	token1, err := rc.AcquireCommitLock()
	if err != nil {
		t.Errorf("Error in AcquireCommitLock: %v", err)
	}
	if token1 == nil {
		t.Error("Should have lock")
	}
	expectLocked(t, rc, token1, true)

	// The lock should be exclusive
	token2, err := rc.AcquireCommitLock()
	if err != nil {
		t.Errorf("Error in AcquireCommitLock: %v", err)
	}
	if token2 != nil {
		t.Error("Lock should be exclusive")
	}
	expectLocked(t, rc, token1, true)

	// Other tokens should be able to acquire the lock after we
	// release it
	rc.ReleaseCommitLock(*token1)
	token4, err := rc.AcquireCommitLock()
	if err != nil {
		t.Errorf("Error in AcquireCommitLock: %v", err)
	}
	if token4 == nil {
		t.Error("Should have acquired lock")
	}
	expectLocked(t, rc, token1, false)
	expectLocked(t, rc, token4, true)

	// Cleanup
	rc.ReleaseCommitLock(*token4)
	expectLocked(t, rc, token4, false)
}

func Test_RedisEpoch(t *testing.T) {
	rc := getRedisCache(t)

	epoch, err := rc.GetEpoch()
	if err != nil {
		t.Error("Should have gotten epoch")
	}

	err = rc.NextEpoch()
	if err != nil {
		t.Error("Should have incremented epoch")
	}

	nextEpoch, err := rc.GetEpoch()
	if err != nil {
		t.Error("Should have gotten epoch")
	}

	if nextEpoch != epoch+1 {
		t.Error("Epoch should have been incremented by 1")
	}
}

func Test_RedisRestore(t *testing.T) {
	rc := getRedisCache(t)

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

	otherLogState := types.CTLogState{
		LogID:          "tpj13e9osHbErk6uYPSZMMR-4ODf3TGGIoDWSVGA1hU=",
		MMD:            86400,
		ShortURL:       "ct.example.com/v1",
		MinEntry:       0,
		MaxEntry:       0,
		MinTimestamp:   0,
		MaxTimestamp:   0,
		LastUpdateTime: time.Now(),
	}

	// Put an entry in the cache to test that logs that are
	// not passed to `Restore` are removed.
	err := rc.StoreLogState(&otherLogState)
	if err != nil {
		t.Error(err)
	}

	_, err = rc.LoadLogState(otherLogState.ShortURL)
	if err != nil {
		t.Errorf("Entry for %s should be present", otherLogState.ShortURL)
	}

	storedEpoch := uint64(31415)
	err = rc.Restore(storedEpoch, []types.CTLogState{logState})
	if err != nil {
		t.Error("Should have modified cache")
	}

	epoch, err := rc.GetEpoch()
	if err != nil || epoch != storedEpoch {
		t.Errorf("Expected epoch %d", storedEpoch)
	}

	_, err = rc.LoadLogState(logState.ShortURL)
	if err != nil {
		t.Errorf("Entry for %s should be present", logState.ShortURL)
	}

	_, err = rc.LoadLogState(otherLogState.ShortURL)
	if err == nil {
		t.Errorf("Entry for %s should not be present", otherLogState.ShortURL)
	}
}

func Test_RedisPreIssuerAlias(t *testing.T) {
	rc := getRedisCache(t)
	issuer1 := types.NewIssuerFromString(kIssuer1)
	issuer2 := types.NewIssuerFromString(kIssuer2)
	issuer3 := types.NewIssuerFromString(kIssuer3)
	aliases, err := rc.GetPreIssuerAliases(issuer1)
	if err != nil {
		t.Error(err)
	}
	if len(aliases) != 0 {
		t.Errorf("Expected 0 alias, found %d", len(aliases))
	}
	err = rc.AddPreIssuerAlias(issuer1, issuer2)
	if err != nil {
		t.Error(err)
	}
	err = rc.AddPreIssuerAlias(issuer1, issuer3)
	if err != nil {
		t.Error(err)
	}
	aliases, err = rc.GetPreIssuerAliases(issuer1)
	if err != nil {
		t.Error(err)
	}
	if len(aliases) != 2 {
		t.Errorf("Expected 2 aliases, found %d", len(aliases))
	}
	if !(kIssuer2 == aliases[0].ID() || kIssuer2 == aliases[1].ID()) {
		t.Errorf("Expected alias %s, found %s and %s", kIssuer2, aliases[0].ID(), aliases[1].ID())
	}
	if !(kIssuer3 == aliases[0].ID() || kIssuer3 == aliases[1].ID()) {
		t.Errorf("Expected alias %s, found %s and %s", kIssuer3, aliases[0].ID(), aliases[1].ID())
	}
	rc.client.FlushDB()
}
