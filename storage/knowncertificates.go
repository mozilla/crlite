package storage

import (
	"encoding/json"
	"github.com/golang/glog"
	"io/ioutil"
	"math/big"
	"os"
	"sort"
	"sync"
)

type KnownCertificates struct {
	mutex    *sync.Mutex
	known    []*big.Int
	filePath string
	perms    os.FileMode
}

func NewKnownCertificates(aKnownPath string, aPerms os.FileMode) *KnownCertificates {
	return &KnownCertificates{
		mutex:    &sync.Mutex{},
		filePath: aKnownPath,
		perms:    aPerms,
		known:    make([]*big.Int, 0, 100),
	}
}

func (kc *KnownCertificates) Load() error {
	kc.mutex.Lock()
	defer kc.mutex.Unlock()

	fd, err := os.Open(kc.filePath)
	if err != nil {
		return err
	}

	data, err := ioutil.ReadAll(fd)
	if err != nil {
		glog.Errorf("Error reading known certificates %s: %s", kc.filePath, err)
	}

	err = json.Unmarshal(data, &kc.known)
	if err != nil {
		glog.Errorf("Error unmarshaling known certificates %s: %s", kc.filePath, err)
	}

	if err = fd.Close(); err != nil {
		glog.Errorf("Error loading known certificates %s: %s", kc.filePath, err)
	}
	return err
}

func (kc *KnownCertificates) Save() error {
	kc.mutex.Lock()
	defer kc.mutex.Unlock()

	fd, err := os.OpenFile(kc.filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, kc.perms)
	if err != nil {
		glog.Errorf("Error opening known certificates %s: %s", kc.filePath, err)
		return err
	}

	data, err := json.Marshal(kc.known)
	if err != nil {
		glog.Errorf("Error marshaling known certificates %s: %s", kc.filePath, err)
	}

	_, err = fd.Write(data)
	if err != nil {
		glog.Errorf("Error writing known certificates %s: %s", kc.filePath, err)
	}

	if err = fd.Close(); err != nil {
		glog.Errorf("Error storing known certificates %s: %s", kc.filePath, err)
	}
	return err
}

// Returns true if this serial was unknown. Subsequent calls with the same serial
// will return false, as it will be known then.
func (kc *KnownCertificates) WasUnknown(aSerial *big.Int) (bool, error) {
	kc.mutex.Lock()
	defer kc.mutex.Unlock()

	count := len(kc.known)

	idx := sort.Search(count, func(i int) bool {
		return aSerial.Cmp(kc.known[i]) <= 0
	})

	var cmp int
	if idx < count {
		cmp = aSerial.Cmp(kc.known[idx])
	}

	if idx < count && cmp == 0 {
		return false, nil
	}

	// Non-allocating insert, see https://github.com/golang/go/wiki/SliceTricks
	kc.known = append(kc.known, nil)
	copy(kc.known[idx+1:], kc.known[idx:])
	kc.known[idx] = aSerial
	return true, nil
}
