package storage

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis"
	"github.com/golang/glog"

	"github.com/mozilla/crlite/go"
)

const EMPTY_QUEUE string = "redis: nil"
const NO_EXPIRATION time.Duration = 0

// The commit lock is acquired in aggregate-known before cached serials are
// written to disk. It is held until aggregate-known is done reading serials
// from disk. We set a 4 hour expiry on the commit lock in case the
// aggregate-known process is abruptly terminated. The commit process is
// fault-tolerant and will not leave persistent storage in a bad state. The
// lock expiry just ensures that the next aggregate-known process will get a
// chance to run.
const COMMIT_LOCK_KEY string = "lock::commit"
const COMMIT_LOCK_EXPIRATION time.Duration = 4 * time.Hour

const EPOCH_KEY string = "epoch"

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
	ir := rc.client.SAdd(key, entry)
	added, err := ir.Result()
	if err != nil && strings.HasPrefix(err.Error(), "OOM") {
		glog.Fatalf("Out of memory on Redis insert of entry %s into key %s, error %v", entry, key, err.Error())
	}
	return added == 1, err
}

func (rc *RedisCache) SetRemove(key string, entries []string) error {
	batchSize := 1024
	for batchStart := 0; batchStart < len(entries); batchStart += batchSize {
		batchEnd := batchStart + batchSize
		if batchEnd > len(entries) {
			batchEnd = len(entries)
		}
		batch := entries[batchStart:batchEnd]
		_, err := rc.client.Pipelined(func(pipe redis.Pipeliner) error {
			for _, entry := range batch {
				err := pipe.SRem(key, entry).Err()
				if err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (rc *RedisCache) SetContains(key string, entry string) (bool, error) {
	br := rc.client.SIsMember(key, entry)
	return br.Result()
}

func (rc *RedisCache) SetList(key string) ([]string, error) {
	slicer := rc.client.SMembers(key)
	return slicer.Result()
}

func (rc *RedisCache) SetToChan(key string, c chan<- string) error {
	defer close(c)
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
	ir := rc.client.Exists(key)
	count, err := ir.Result()
	return count == 1, err
}

func (rc *RedisCache) ExpireAt(key string, aExpTime time.Time) error {
	br := rc.client.ExpireAt(key, aExpTime)
	return br.Err()
}

func (rc *RedisCache) KeysToChan(pattern string, c chan<- string) error {
	defer close(c)
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

func shortUrlToLogKey(shortUrl string) string {
	return fmt.Sprintf("log::%s", strings.TrimRight(shortUrl, "/"))
}

func (ec *RedisCache) Migrate(logData *types.CTLogMetadata) error {
	logUrlObj, err := url.Parse(logData.URL)
	if err != nil {
		return err
	}

	shortUrl := logUrlObj.Host + strings.TrimRight(logUrlObj.Path, "/")
	newKey := shortUrlToLogKey(shortUrl)
	_, err = ec.client.Get(newKey).Bytes()
	if err != nil && err != redis.Nil {
		return err
	}
	haveNew := err != redis.Nil

	oldKey := newKey + "/"
	oldData, err := ec.client.Get(oldKey).Bytes()
	if err != nil && err != redis.Nil {
		return err
	}
	haveOld := err != redis.Nil

	// If we have both new and old data, then just delete old.
	if haveOld && haveNew {
		ec.client.Del(oldKey)
		return nil
	}

	// If we have old data but not new, migrate.
	if haveOld {
		var log types.CTLogState
		if err = json.Unmarshal(oldData, &log); err != nil {
			return err
		}
		if err = ec.StoreLogState(&log); err != nil {
			return err
		}
		ec.client.Del(oldKey)
		return nil
	}

	// No data. Nothing to do.
	return nil
}

func (ec *RedisCache) StoreLogState(log *types.CTLogState) error {
	encoded, err := json.Marshal(log)
	if err != nil {
		return err
	}

	return ec.client.Set(shortUrlToLogKey(log.ShortURL), encoded, NO_EXPIRATION).Err()
}

func (ec *RedisCache) LoadLogState(shortUrl string) (*types.CTLogState, error) {
	data, err := ec.client.Get(shortUrlToLogKey(shortUrl)).Bytes()
	if err != nil {
		return nil, err
	}

	var log types.CTLogState
	if err = json.Unmarshal(data, &log); err != nil {
		return nil, err
	}
	return &log, nil
}

func (ec *RedisCache) LoadAllLogStates() ([]types.CTLogState, error) {
	ctLogList := make([]types.CTLogState, 0)
	keyChan := make(chan string)
	go func() {
		err := ec.KeysToChan("log::*", keyChan)
		if err != nil {
			glog.Fatalf("Couldn't list CT logs from cache: %s", err)
		}
	}()

	for entry := range keyChan {
		data, err := ec.client.Get(entry).Bytes()
		if err != nil {
			return nil, fmt.Errorf("Couldn't parse CT logs metadata: %s", err)
		}

		ctLogList = append(ctLogList, types.CTLogState{})
		if err := json.Unmarshal(data, &ctLogList[len(ctLogList)-1]); err != nil {
			return nil, fmt.Errorf("Couldn't parse CT logs metadata: %s", err)
		}
	}

	return ctLogList, nil
}

func (ec *RedisCache) AcquireCommitLock() (*string, error) {
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, err
	}
	commitLockToken := base64.URLEncoding.EncodeToString(randomBytes)

	// SETNX is a set-if-not-set primitive. Returns true if commitLockToken
	// is the new value associated with COMMIT_LOCK_KEY. Returns false or
	// an error otherwise.
	set, err := ec.client.SetNX(COMMIT_LOCK_KEY, commitLockToken, COMMIT_LOCK_EXPIRATION).Result()
	if err != nil || !set {
		return nil, err
	}
	return &commitLockToken, err
}

func (ec *RedisCache) ReleaseCommitLock(aToken string) {
	hasLock, err := ec.HasCommitLock(aToken)
	if err == nil && hasLock {
		ec.client.Del(COMMIT_LOCK_KEY)
	}
}

func (ec *RedisCache) HasCommitLock(aToken string) (bool, error) {
	lockHolder, err := ec.client.Get(COMMIT_LOCK_KEY).Result()
	if err == redis.Nil { // COMMIT_LOCK_KEY not set
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return lockHolder == aToken, nil
}

func (ec *RedisCache) GetEpoch() (uint64, error) {
	epochStr, err := ec.client.Get(EPOCH_KEY).Result()
	if err == redis.Nil { // EPOCH_KEY not set
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(epochStr, 10, 64)
}

func (ec *RedisCache) NextEpoch() error {
	return ec.client.Incr(EPOCH_KEY).Err()
}

func (ec *RedisCache) Restore(aEpoch uint64, aLogStates []types.CTLogState) error {
	commitToken, err := ec.AcquireCommitLock()
	if err != nil || commitToken == nil {
		return fmt.Errorf("Failed to acquire commit lock: %s", err)
	}
	defer ec.ReleaseCommitLock(*commitToken)

	logKeys, err := ec.client.Keys("log::*").Result()
	if err != nil {
		return err
	}

	for _, logKey := range logKeys {
		err = ec.client.Del(logKey).Err()
		if err != nil {
			return err
		}
	}

	for _, logState := range aLogStates {
		err := ec.StoreLogState(&logState)
		if err != nil {
			return err
		}
	}

	err = ec.client.Set(EPOCH_KEY, aEpoch, NO_EXPIRATION).Err()
	if err != nil {
		return err
	}

	return nil
}
