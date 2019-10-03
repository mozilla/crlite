package storage

import (
	"github.com/go-redis/redis"
	"github.com/golang/glog"
)

type RedisCache struct {
	client *redis.Client
}

func NewRedisCache(addr string) (*RedisCache, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr: addr,
	})

	statusr := rdb.Ping()
	if statusr.Err() != nil {
		return nil, statusr.Err()
	}

	return &RedisCache{rdb}, nil
}

func (rc *RedisCache) SortedInsert(key string, entry string) (bool, error) {
	ir := rc.client.ZAdd(key, redis.Z{
		Score:  0,
		Member: entry,
	})
	added, err := ir.Result()
	return added == 1, err
}

func (rc *RedisCache) SortedContains(key string, entry string) (bool, error) {
	fr := rc.client.ZScore(key, entry)
	if fr.Err() != nil {
		if fr.Err().Error() == "redis: nil" {
			glog.V(3).Infof("Redis does not contain key=%s, entry=%s", key, entry)
			return false, nil
		}
		glog.Warningf("Error at Redis caught, key=%s, entry=%s, err=%+v", key, entry, fr.Err())
		return false, fr.Err()
	}
	return true, nil
}

func (rc *RedisCache) SortedList(key string) ([]string, error) {
	slicer := rc.client.ZRange(key, 0, -1)
	return slicer.Result()
}

func (rc *RedisCache) Exists(key string) (bool, error) {
	ir := rc.client.Exists(key)
	count, err := ir.Result()
	return count == 1, err
}
