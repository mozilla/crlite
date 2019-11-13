package storage

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"
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
	rc := getRedisCache(t)
	if err := rc.MemoryPolicyCorrect(); err != nil {
		t.Error(err)
	}
}

func Test_RedisInvalidHost(t *testing.T) {
	_, err := NewRedisCache("unknown_host:999999", time.Second)
	if err == nil {
		t.Error("Should have failed to construct invalid redis cache host")
	}
}

func Test_RedisInsertion(t *testing.T) {
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
}

func Test_RedisSortedCache(t *testing.T) {
	rc := getRedisCache(t)
	defer rc.client.Del("sortedCache")

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
		success, err := rc.SetInsert("sortedCache", s)
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
		exists, err := rc.SetContains("sortedCache", s)
		if err != nil {
			t.Error(err)
		}
		if exists != true {
			t.Errorf("Should have existed! %s", s)
		}
	}

	list, err := rc.SetList("sortedCache")
	if err != nil {
		t.Error(err)
	}
	if len(list) != len(sortedSerials) {
		t.Errorf("Expected %d serials but got %d", len(sortedSerials), len(list))
	}
}

func BenchmarkSortedCacheInsertion(b *testing.B) {
	rc := getRedisCache(b)
	defer rc.client.Del("sortedCacheBenchmark")

	var i uint64
	for i = 0; i < uint64(b.N); i++ {
		buf := make([]byte, binary.Size(i))
		binary.BigEndian.PutUint64(buf, i)
		serial := NewSerialFromHex(hex.EncodeToString(buf))
		_, err := rc.SetInsert("sortedCacheBenchmark", serial.String())
		if err != nil {
			b.Error(err)
		}
	}

	b.StopTimer()
}

func Test_RedisExpiration(t *testing.T) {
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

func queueInsert(t *testing.T, q string, v string, count int64, rc *RedisCache) {
	c, err := rc.Queue(q, v)
	if err != nil {
		t.Error(err)
	}
	if c != count {
		t.Errorf("Expected a queue length of %d but got %d", count, c)
	}
}

func queueExpect(t *testing.T, q string, v string, rc *RedisCache) {
	result, err := rc.Pop(q)
	if err != nil {
		t.Error(err)
	}
	if result != v {
		t.Errorf("Expected %s, got %s", v, result)
	}
}

func Test_RedisQueue(t *testing.T) {
	q := "queueTest"
	rc := getRedisCache(t)
	defer rc.client.Del(q)

	queueInsert(t, q, "one", 1, rc)
	queueInsert(t, q, "two", 2, rc)
	queueInsert(t, q, "three", 3, rc)

	queueExpect(t, q, "one", rc)

	queueInsert(t, q, "four", 3, rc)

	queueExpect(t, q, "two", rc)
	queueExpect(t, q, "three", rc)
	queueExpect(t, q, "four", rc)

	result, err := rc.QueueLength(q)
	if err != nil {
		t.Error(err)
	}
	if result != 0 {
		t.Errorf("Queue should be empty")
	}

	_, err = rc.Pop(q)
	if err.Error() != EMPTY_QUEUE {
		t.Errorf("Expected %s but got %s", EMPTY_QUEUE, err)
	}

	queueInsert(t, q, "five", 1, rc)
	result, err = rc.QueueLength(q)
	if err != nil {
		t.Error(err)
	}
	if result != 1 {
		t.Errorf("Queue should no longer be empty")
	}
}

func Test_RedisKeyList(t *testing.T) {
	queues := []string{
		"2019-01-01-01::issuer",
		"2019-01-01-02::issuer",
		"2019-01-01-03::issuer",
		"2019-01-02-15::issuer",
		"2019-01-01-01::otherissuer",
		"2019-01-01-02::otherissuer",
		"2019-01-01-03::otherissuer",
		"2019-01-05::otherissuer",
	}
	rc := getRedisCache(t)
	for _, q := range queues {
		queueInsert(t, q, "entry", 1, rc)
	}
	defer func() {
		for _, q := range queues {
			rc.client.Del(q)
		}
	}()

	l, err := rc.Keys("2019-01-01*::issuer")
	if err != nil {
		t.Error(err)
	}
	if len(l) != 3 {
		t.Errorf("Expected 3 entries matching 2019-01-01*::issuer, got %+v", l)
	}

	l, err = rc.Keys("2019-01-05*::otherissuer")
	if err != nil {
		t.Error(err)
	}
	if len(l) != 1 {
		t.Errorf("Expected 1 entry matching 2019-01-05*::otherissuer, got %+v", l)
	}

	l, err = rc.Keys("2019-01-01-03*::otherissuer")
	if err != nil {
		t.Error(err)
	}
	if len(l) != 1 {
		t.Errorf("Expected 1 entry matching 2019-01-01-03*::otherissuer, got %+v", l)
	}

	l, err = rc.Keys("2019-01-01-03*::unknownissuer")
	if err != nil {
		t.Error(err)
	}
	if len(l) != 0 {
		t.Errorf("Expected no matches for unknownissuer, got %+v", l)
	}
}
