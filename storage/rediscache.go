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

func (rc *RedisCache) SortedInsert(key string, serial Serial) (bool, error) {
	ir := rc.client.ZAdd(key, redis.Z{
		Score:  0,
		Member: serial.String(),
	})
	added, err := ir.Result()
	return added == 1, err
}

func (rc *RedisCache) SortedContains(key string, serial Serial) (bool, error) {
	fr := rc.client.ZScore(key, serial.String())
	if fr.Err() != nil {
		if fr.Err().Error() == "redis: nil" {
			glog.V(3).Infof("Redis does not contain key=%s, serial=%s", key, serial)
			return false, nil
		}
		glog.Warningf("Error at Redis caught, key=%s, serial=%s, err=%+v", key, serial, fr.Err())
		return false, fr.Err()
	}
	return true, nil
}

func (rc *RedisCache) SortedList(key string) ([]Serial, error) {
	slicer := rc.client.ZRange(key, 0, -1)
	strList, err := slicer.Result()
	if err != nil {
		return []Serial{}, err
	}

	serials := make([]Serial, len(strList))
	for i, str := range strList {
		serials[i] = NewSerialFromHex(str)
	}

	return serials, nil
}
