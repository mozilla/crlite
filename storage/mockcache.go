package storage

import (
	"sort"
	"strings"

	"github.com/golang/glog"
)

type MockRemoteCache struct {
	Data map[string][]string
}

func NewMockRemoteCache() *MockRemoteCache {
	return &MockRemoteCache{
		Data: make(map[string][]string),
	}
}

func (ec *MockRemoteCache) SortedInsert(key string, entry string) (bool, error) {
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

func (ec *MockRemoteCache) SortedContains(key string, entry string) (bool, error) {
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

func (ec *MockRemoteCache) SortedList(key string) ([]string, error) {
	return ec.Data[key], nil
}

func (ec *MockRemoteCache) Exists(key string) (bool, error) {
	_, ok := ec.Data[key]
	return ok, nil
}
