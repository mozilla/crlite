package storage

import (
	"sort"

	"github.com/golang/glog"
)

type MockRemoteCache struct {
	Data map[string][]Serial
}

func NewMockRemoteCache() *MockRemoteCache {
	return &MockRemoteCache{
		Data: make(map[string][]Serial),
	}
}

func (ec *MockRemoteCache) SortedInsert(key string, serial Serial) (bool, error) {
	count := len(ec.Data[key])

	idx := sort.Search(count, func(i int) bool {
		return serial.Cmp(ec.Data[key][i]) <= 0
	})

	var cmp int
	if idx < count {
		cmp = serial.Cmp(ec.Data[key][idx])
	}

	if idx < count && cmp == 0 {
		glog.V(3).Infof("[%s] Certificate already known: %s (pos=%d)", key, serial, idx)
		return false, nil
	}

	// Non-allocating insert, see https://github.com/golang/go/wiki/SliceTricks
	glog.V(3).Infof("[%s] Certificate unknown: %s (pos=%d)", key, serial, idx)
	ec.Data[key] = append(ec.Data[key], Serial{})
	copy(ec.Data[key][idx+1:], ec.Data[key][idx:])
	ec.Data[key][idx] = serial
	return true, nil
}

func (ec *MockRemoteCache) SortedContains(key string, serial Serial) (bool, error) {
	count := len(ec.Data[key])

	idx := sort.Search(count, func(i int) bool {
		return serial.Cmp(ec.Data[key][i]) <= 0
	})

	var cmp int
	if idx < count {
		cmp = serial.Cmp(ec.Data[key][idx])
	}

	if idx < count && cmp == 0 {
		return true, nil
	}

	return false, nil
}

func (ec *MockRemoteCache) SortedList(key string) ([]Serial, error) {
	return ec.Data[key], nil
}
