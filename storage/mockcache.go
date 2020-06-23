package storage

import (
	"encoding/json"
	"fmt"
	"path/filepath" // used for glob-like matching in Keys
	"sort"
	"strings"
	"time"

	"github.com/golang/glog"
)

type MockRemoteCache struct {
	Data        map[string][]string
	LogData     map[string][]string
	Expirations map[string]time.Time
	Duplicate   int
}

func NewMockRemoteCache() *MockRemoteCache {
	return &MockRemoteCache{
		Data:        make(map[string][]string),
		LogData:     make(map[string][]string),
		Expirations: make(map[string]time.Time),
		Duplicate:   0,
	}
}

func (ec *MockRemoteCache) CleanupExpiry() {
	now := time.Now()
	for key, timestamp := range ec.Expirations {
		if timestamp.Before(now) {
			delete(ec.Data, key)
			delete(ec.Expirations, key)
		}
	}
}

func (ec *MockRemoteCache) SetInsert(key string, entry string) (bool, error) {
	count := len(ec.Data[key])

	idx := sort.Search(count, func(i int) bool {
		return strings.Compare(entry, ec.Data[key][i]) <= 0
	})

	var cmp int
	if idx < count {
		cmp = strings.Compare(entry, ec.Data[key][idx])
	}

	if idx < count && cmp == 0 {
		glog.V(3).Infof("[%s] Entry already known: %s (pos=%d)", key, entry, idx)
		return false, nil
	}

	// Non-allocating insert, see https://github.com/golang/go/wiki/SliceTricks
	glog.V(3).Infof("[%s] Entry unknown: %s (pos=%d)", key, entry, idx)
	ec.Data[key] = append(ec.Data[key], "")
	copy(ec.Data[key][idx+1:], ec.Data[key][idx:])
	ec.Data[key][idx] = entry
	return true, nil
}

func (ec *MockRemoteCache) SetRemove(key string, entry string) (bool, error) {
	ec.CleanupExpiry()
	count := len(ec.Data[key])

	idx := sort.Search(count, func(i int) bool {
		return strings.Compare(entry, ec.Data[key][i]) <= 0
	})

	var cmp int
	if idx < count {
		cmp = strings.Compare(entry, ec.Data[key][idx])
	}

	if idx < count && cmp == 0 {
		ec.Data[key] = append(ec.Data[key][:idx], ec.Data[key][idx:]...)
		return true, nil
	}

	return false, nil
}

func (ec *MockRemoteCache) SetContains(key string, entry string) (bool, error) {
	ec.CleanupExpiry()
	count := len(ec.Data[key])

	idx := sort.Search(count, func(i int) bool {
		return strings.Compare(entry, ec.Data[key][i]) <= 0
	})

	var cmp int
	if idx < count {
		cmp = strings.Compare(entry, ec.Data[key][idx])
	}

	if idx < count && cmp == 0 {
		return true, nil
	}

	return false, nil
}

func (ec *MockRemoteCache) SetList(key string) ([]string, error) {
	ec.CleanupExpiry()
	return ec.Data[key], nil
}

func (ec *MockRemoteCache) SetToChan(key string, c chan<- string) error {
	defer close(c)
	ec.CleanupExpiry()
	for i := 0; i < ec.Duplicate+1; i++ {
		for _, v := range ec.Data[key] {
			c <- v
		}
	}
	return nil
}

func (ec *MockRemoteCache) SetCardinality(key string) (int, error) {
	return len(ec.Data[key]), nil
}

func (ec *MockRemoteCache) Exists(key string) (bool, error) {
	ec.CleanupExpiry()
	_, ok := ec.Data[key]
	return ok, nil
}

func (ec *MockRemoteCache) ExpireAt(key string, expTime time.Time) error {
	ec.Expirations[key] = expTime
	return nil
}

func (ec *MockRemoteCache) ExpireIn(key string, dur time.Duration) error {
	ec.Expirations[key] = time.Now().Add(dur)
	return nil
}

func (ec *MockRemoteCache) Queue(key string, identifier string) (int64, error) {
	return int64(0), fmt.Errorf("Queue unimplemented")
}

func (ec *MockRemoteCache) Pop(key string) (string, error) {
	return "", fmt.Errorf("Pop unimplemented")
}

func (ec *MockRemoteCache) QueueLength(key string) (int64, error) {
	return int64(0), fmt.Errorf("QueueLength unimplemented")
}

func (ec *MockRemoteCache) KeysToChan(pattern string, c chan<- string) error {
	defer close(c)

	for key := range ec.Data {
		matched, err := filepath.Match(pattern, key)
		if err != nil {
			return err
		}
		if matched {
			c <- key
		}
	}

	return nil
}

func (ec *MockRemoteCache) TrySet(key string, v string, life time.Duration) (string, error) {
	val, ok := ec.Data[key]
	if ok {
		return val[0], nil
	}
	ec.Data[key] = []string{v}
	err := ec.ExpireAt(key, time.Now().Add(life))
	return v, err
}

func (ec *MockRemoteCache) BlockingPopCopy(key string, dest string,
	timeout time.Duration) (string, error) {
	v, err := ec.Pop(key)
	if err != nil {
		return "", err
	}
	_, err = ec.Queue(dest, v)
	if err != nil {
		return "", err
	}
	return v, err
}

func (ec *MockRemoteCache) ListRemove(key string, value string) error {
	_, err := ec.SetRemove(key, value)
	return err
}

func (ec *MockRemoteCache) StoreLogState(log *CertificateLog) error {
	encoded, err := json.Marshal(log)
	if err != nil {
		return err
	}

	ec.LogData[log.ShortURL] = []string{string(encoded)}
	return nil
}

func (ec *MockRemoteCache) LoadLogState(shortUrl string) (*CertificateLog, error) {
	data, ok := ec.LogData[shortUrl]
	if !ok {
		return nil, fmt.Errorf("Log state not found")
	}
	if len(data) != 1 {
		return nil, fmt.Errorf("Unexpected number of log states")
	}

	var log CertificateLog
	if err := json.Unmarshal([]byte(data[0]), &log); err != nil {
		return nil, err
	}
	return &log, nil
}

func (ec *MockRemoteCache) GetAllLogStates() ([]*CertificateLog, error) {
	objects := []*CertificateLog{}
	for key := range ec.LogData {
		state, err := ec.LoadLogState(key)
		if err != nil {
			return objects, err
		}
		objects = append(objects, state)
	}
	return objects, nil
}
