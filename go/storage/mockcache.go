package storage

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath" // used for glob-like matching in Keys
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/mozilla/crlite/go"
)

type MockRemoteCache struct {
	mu          sync.Mutex
	Data        map[string][]string
	Expirations map[string]time.Time
	Duplicate   int
	CommitLock  *string
	Epoch       uint64
}

func NewMockRemoteCache() *MockRemoteCache {
	return &MockRemoteCache{
		Data:        make(map[string][]string),
		Expirations: make(map[string]time.Time),
		Duplicate:   0,
	}
}

func (ec *MockRemoteCache) cleanupExpiry() {
	// ec.mu must be held
	now := time.Now()
	for key, timestamp := range ec.Expirations {
		if timestamp.Before(now) {
			delete(ec.Data, key)
			delete(ec.Expirations, key)
		}
	}
}

func (ec *MockRemoteCache) SetInsert(key string, entry string) (bool, error) {
	ec.mu.Lock()
	defer ec.mu.Unlock()
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

func (ec *MockRemoteCache) setRemove(key string, entry string) error {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	count := len(ec.Data[key])

	idx := sort.Search(count, func(i int) bool {
		return strings.Compare(entry, ec.Data[key][i]) <= 0
	})

	var cmp int
	if idx < count {
		cmp = strings.Compare(entry, ec.Data[key][idx])
	}

	if idx < count && cmp == 0 {
		if count == 1 {
			delete(ec.Data, key)
		} else {
			ec.Data[key][idx] = ec.Data[key][count-1]
			ec.Data[key] = ec.Data[key][:count-1]
		}
		return nil
	}

	return nil
}

func (ec *MockRemoteCache) SetRemove(key string, entries []string) error {
	for _, entry := range entries {
		err := ec.setRemove(key, entry)
		if err != nil {
			return err
		}
	}
	ec.mu.Lock()
	defer ec.mu.Unlock()
	ec.cleanupExpiry()
	return nil
}

func (ec *MockRemoteCache) SetContains(key string, entry string) (bool, error) {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	ec.cleanupExpiry()
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
	ec.mu.Lock()
	defer ec.mu.Unlock()
	ec.cleanupExpiry()
	return ec.Data[key], nil
}

func (ec *MockRemoteCache) SetToChan(key string, c chan<- string) error {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	defer close(c)
	ec.cleanupExpiry()
	for i := 0; i < ec.Duplicate+1; i++ {
		for _, v := range ec.Data[key] {
			c <- v
		}
	}
	return nil
}

func (ec *MockRemoteCache) SetCardinality(key string) (int, error) {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	return len(ec.Data[key]), nil
}

func (ec *MockRemoteCache) Exists(key string) (bool, error) {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	ec.cleanupExpiry()
	_, ok := ec.Data[key]
	return ok, nil
}

func (ec *MockRemoteCache) ExpireAt(key string, expTime time.Time) error {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	ec.Expirations[key] = expTime
	return nil
}

func (ec *MockRemoteCache) KeysToChan(pattern string, c chan<- string) error {
	ec.mu.Lock()
	defer ec.mu.Unlock()
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
	ec.mu.Lock()
	defer ec.mu.Unlock()
	encoded, err := json.Marshal(log)
	if err != nil {
		return err
	}

	ec.Data["log::"+log.ShortURL] = []string{string(encoded)}
	return nil
}

func (ec *MockRemoteCache) LoadLogState(shortUrl string) (*types.CTLogState, error) {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	data, ok := ec.Data["log::"+shortUrl]
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
	ec.mu.Lock()
	defer ec.mu.Unlock()
	var logStates []types.CTLogState
	for key, value := range ec.Data {
		if strings.HasPrefix(key, "log::") {
			var log types.CTLogState
			if err := json.Unmarshal([]byte(value[0]), &log); err != nil {
				return nil, err
			}
			logStates = append(logStates, log)
		}
	}
	return logStates, nil
}

func (ec *MockRemoteCache) Migrate(logData *types.CTLogMetadata) error {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	return nil
}

func (ec *MockRemoteCache) AcquireCommitLock() (*string, error) {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, err
	}
	commitLockToken := base64.URLEncoding.EncodeToString(randomBytes)
	if ec.CommitLock == nil {
		ec.CommitLock = &commitLockToken
		return &commitLockToken, nil
	}
	return nil, nil
}

func (ec *MockRemoteCache) ReleaseCommitLock(aToken string) {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	hasLock := ec.CommitLock != nil && *ec.CommitLock == aToken
	if hasLock {
		ec.CommitLock = nil
	}
}

func (ec *MockRemoteCache) HasCommitLock(aToken string) (bool, error) {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	return ec.CommitLock != nil && *ec.CommitLock == aToken, nil
}

func (ec *MockRemoteCache) GetEpoch() (uint64, error) {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	return ec.Epoch, nil
}

func (ec *MockRemoteCache) NextEpoch() error {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	ec.Epoch += 1
	return nil
}

func (ec *MockRemoteCache) Restore(aEpoch uint64, aLogStates []types.CTLogState) error {
	ec.mu.Lock()
	ec.Epoch = aEpoch
	ec.mu.Unlock()

	for key, _ := range ec.Data {
		if strings.HasPrefix(key, "log::") {
			delete(ec.Data, key)
		}
	}

	for _, logState := range aLogStates {
		err := ec.StoreLogState(&logState)
		if err != nil {
			return err
		}
	}

	return nil
}
