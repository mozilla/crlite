package storage

import (
	"encoding/json"
	"fmt"
	"path/filepath" // used for glob-like matching in Keys
	"sort"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/mozilla/crlite/go"
)

type MockRemoteCache struct {
	Data        map[string][]string
	Expirations map[string]time.Time
	Duplicate   int
}

func NewMockRemoteCache() *MockRemoteCache {
	return &MockRemoteCache{
		Data:        make(map[string][]string),
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

func (ec *MockRemoteCache) StoreLogState(log *types.CTLogState) error {
	encoded, err := json.Marshal(log)
	if err != nil {
		return err
	}

	ec.Data[log.ShortURL] = []string{string(encoded)}
	return nil
}

func (ec *MockRemoteCache) LoadLogState(shortUrl string) (*types.CTLogState, error) {
	data, ok := ec.Data[shortUrl]
	if !ok {
		return nil, fmt.Errorf("Log state not found")
	}
	if len(data) != 1 {
		return nil, fmt.Errorf("Unexpected number of log states")
	}

	var log types.CTLogState
	if err := json.Unmarshal([]byte(data[0]), &log); err != nil {
		return nil, err
	}
	return &log, nil
}

func (ec *MockRemoteCache) LoadAllLogStates() ([]types.CTLogState, error) {
	return nil, fmt.Errorf("Unimplemented")
}

func (ec *MockRemoteCache) Migrate(logData *types.CTLogMetadata) error {
	return nil
}
