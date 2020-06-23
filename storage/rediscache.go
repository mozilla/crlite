package storage

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/armon/go-metrics"
	"github.com/go-redis/redis"
	"github.com/golang/glog"
)

const EMPTY_QUEUE string = "redis: nil"
const NO_EXPIRATION time.Duration = 0
const LOG_PREFIX string = "log::"

type RedisCache struct {
	client *redis.Client
}

func NewRedisCache(addr string, cacheTimeout time.Duration) (*RedisCache, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:            addr,
		MaxRetries:      10,
		MaxRetryBackoff: 5 * time.Second,
		ReadTimeout:     cacheTimeout,
		WriteTimeout:    cacheTimeout,
	})

	statusr := rdb.Ping()
	if statusr.Err() != nil {
		return nil, statusr.Err()
	}

	rc := &RedisCache{rdb}
	err := rc.MemoryPolicyCorrect()
	if err != nil {
		glog.Warning(err)
	}

	return rc, nil
}

func (rc *RedisCache) MemoryPolicyCorrect() error {
	// maxmemory_policy should be `noeviction`
	confr := rc.client.Info("memory")
	if confr.Err() != nil {
		return confr.Err()
	}
	if strings.Contains(confr.Val(), "maxmemory_policy:noeviction") {
		return nil
	}
	return fmt.Errorf("Redis maxmemory_policy should be `noeviction`. Memory config is set to %s",
		confr.Val())
}

func (rc *RedisCache) SetInsert(key string, entry string) (bool, error) {
	defer metrics.MeasureSince([]string{"SetInsert"}, time.Now())
	ir := rc.client.SAdd(key, entry)
	added, err := ir.Result()
	if err != nil && strings.HasPrefix(err.Error(), "OOM") {
		glog.Fatalf("Out of memory on Redis insert of entry %s into key %s, error %v", entry, key, err.Error())
	}
	return added == 1, err
}

func (rc *RedisCache) SetRemove(key string, entry string) (bool, error) {
	defer metrics.MeasureSince([]string{"SetRemove"}, time.Now())
	ir := rc.client.SRem(key, entry)
	removed, err := ir.Result()
	return removed > 0, err
}

func (rc *RedisCache) SetContains(key string, entry string) (bool, error) {
	defer metrics.MeasureSince([]string{"SetContains"}, time.Now())
	br := rc.client.SIsMember(key, entry)
	return br.Result()
}

func (rc *RedisCache) SetList(key string) ([]string, error) {
	defer metrics.MeasureSince([]string{"List"}, time.Now())
	slicer := rc.client.SMembers(key)
	return slicer.Result()
}

func (rc *RedisCache) SetToChan(key string, c chan<- string) error {
	defer close(c)
	defer metrics.MeasureSince([]string{"SetToChan"}, time.Now())
	scanres := rc.client.SScan(key, 0, "", 0)
	err := scanres.Err()
	if err != nil {
		return err
	}

	iter := scanres.Iterator()

	for iter.Next() {
		c <- iter.Val()
	}

	return iter.Err()
}

func (rc *RedisCache) SetCardinality(key string) (int, error) {
	v, err := rc.client.SCard(key).Result()
	return int(v), err
}

func (rc *RedisCache) Exists(key string) (bool, error) {
	defer metrics.MeasureSince([]string{"Exists"}, time.Now())
	ir := rc.client.Exists(key)
	count, err := ir.Result()
	return count == 1, err
}

func (rc *RedisCache) ExpireAt(key string, aExpTime time.Time) error {
	defer metrics.MeasureSince([]string{"ExpireAt"}, time.Now())
	br := rc.client.ExpireAt(key, aExpTime)
	return br.Err()
}

func (rc *RedisCache) ExpireIn(key string, aDuration time.Duration) error {
	br := rc.client.Expire(key, aDuration)
	return br.Err()
}

func (rc *RedisCache) Queue(key string, identifier string) (int64, error) {
	ir := rc.client.RPush(key, identifier)
	return ir.Result()
}

func (rc *RedisCache) BlockingPopCopy(key string, dest string,
	timeout time.Duration) (string, error) {
	sr := rc.client.BRPopLPush(key, dest, timeout)
	return sr.Result()
}

func (rc *RedisCache) ListRemove(key string, value string) error {
	ir := rc.client.LRem(key, 1, value)
	return ir.Err()
}

func (rc *RedisCache) Pop(key string) (string, error) {
	sr := rc.client.LPop(key)
	return sr.Result()
}

func (rc *RedisCache) QueueLength(key string) (int64, error) {
	ir := rc.client.LLen(key)
	return ir.Result()
}

func (rc *RedisCache) KeysToChan(pattern string, c chan<- string) error {
	defer close(c)
	defer metrics.MeasureSince([]string{"KeysToChan"}, time.Now())
	scanres := rc.client.Scan(0, pattern, 0)
	err := scanres.Err()
	if err != nil {
		return err
	}

	iter := scanres.Iterator()

	for iter.Next() {
		c <- iter.Val()
	}

	return iter.Err()
}

func (rc *RedisCache) TrySet(k string, v string, life time.Duration) (string, error) {
	br := rc.client.SetNX(k, v, life)
	if br.Err() != nil {
		return "", br.Err()
	}
	sr := rc.client.Get(k)
	return sr.Result()
}

func shortUrlToLogKey(shortUrl string) string {
	return LOG_PREFIX + shortUrl
}

func (ec *RedisCache) StoreLogState(log *CertificateLog) error {
	encoded, err := json.Marshal(log)
	if err != nil {
		return err
	}

	return ec.client.Set(shortUrlToLogKey(log.ShortURL), encoded, NO_EXPIRATION).Err()
}

func (ec *RedisCache) LoadLogState(shortUrl string) (*CertificateLog, error) {
	data, err := ec.client.Get(shortUrlToLogKey(shortUrl)).Bytes()
	if err != nil {
		return nil, err
	}

	var log CertificateLog
	if err = json.Unmarshal(data, &log); err != nil {
		return nil, err
	}
	return &log, nil
}

func (ec *RedisCache) GetAllLogStates() ([]*CertificateLog, error) {
	logList := []*CertificateLog{}
	scanres := ec.client.Scan(0, shortUrlToLogKey("*"), 0)
	err := scanres.Err()
	if err != nil {
		return logList, err
	}

	iter := scanres.Iterator()

	for iter.Next() {
		keyName := iter.Val()
		obj, err := ec.LoadLogState(strings.TrimPrefix(keyName, LOG_PREFIX))
		if err != nil {
			return logList, err
		}
		logList = append(logList, obj)
	}

	return logList, iter.Err()
}
