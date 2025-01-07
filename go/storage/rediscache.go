package storage

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/go-redis/redis"
	"github.com/golang/glog"

	"github.com/mozilla/crlite/go"
)

const EMPTY_QUEUE string = "redis: nil"
const NO_EXPIRATION time.Duration = 0

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

func (rc *RedisCache) SetRemove(key string, entry string) (bool, error) {
	ir := rc.client.SRem(key, entry)
	removed, err := ir.Result()
	return removed > 0, err
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
