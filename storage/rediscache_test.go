package storage

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"reflect"
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

	rc, err := NewRedisCache(setting)
	if err != nil {
		tb.Errorf("Couldn't construct RedisCache: %v", err)
	}
	return rc
}

func Test_RedisInvalidHost(t *testing.T) {
	_, err := NewRedisCache("unknown_host:999999")
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

	firstInsert, err := rc.SortedInsert("key", "FADEC00DEAD00DEAF00CAFE0")
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

	doubleInsert, err := rc.SortedInsert("key", "FADEC00DEAD00DEAF00CAFE0")
	if err != nil {
		t.Error(err)
	}
	if doubleInsert == true {
		t.Errorf("Shouldn't have re-inserted")
	}

	shouldntExist, err := rc.SortedContains("key", "BEAC040FBAC040")
	if err != nil {
		t.Error(err)
	}
	if shouldntExist == true {
		t.Errorf("This serial should not have been saved")
	}

	shouldExist, err := rc.SortedContains("key", "FADEC00DEAD00DEAF00CAFE0")
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
		success, err := rc.SortedInsert("sortedCache", s)
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
		exists, err := rc.SortedContains("sortedCache", s)
		if err != nil {
			t.Error(err)
		}
		if exists != true {
			t.Errorf("Should have existed! %s", s)
		}
	}

	list, err := rc.SortedList("sortedCache")
	if err != nil {
		t.Error(err)
	}
	if len(list) != len(sortedSerials) {
		t.Errorf("Expected %d serials but got %d", len(sortedSerials), len(list))
	}
	if !reflect.DeepEqual(list, sortedSerials) {
		t.Errorf("Expected equal lists. expected=%+v got=%+v", sortedSerials, list)
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
		_, err := rc.SortedInsert("sortedCacheBenchmark", serial.String())
		if err != nil {
			b.Error(err)
		}
	}

	b.StopTimer()
}

func Test_RedisExpiration(t *testing.T) {
	rc := getRedisCache(t)
	defer rc.client.Del("expTest")

	success, err := rc.SortedInsert("expTest", "a")
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
