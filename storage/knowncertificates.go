package storage

import (
	"fmt"
	"math/big"
	"sort"
	"sync"

	"github.com/golang/glog"
)

type KnownCertificates struct {
	mutex   *sync.Mutex
	known   []*big.Int
	expDate string
	issuer  Issuer
	backend StorageBackend
}

func NewKnownCertificates(aExpDate string, aIssuer Issuer, aBackend StorageBackend) *KnownCertificates {
	return &KnownCertificates{
		mutex:   &sync.Mutex{},
		expDate: aExpDate,
		issuer:  aIssuer,
		backend: aBackend,
		known:   make([]*big.Int, 0, 100),
	}
}

func (kc *KnownCertificates) id() string {
	return kc.expDate + "::" + kc.issuer.ID()
}

func (kc *KnownCertificates) Load() error {
	kc.mutex.Lock()
	defer kc.mutex.Unlock()

	data, err := kc.backend.LoadIssuerKnownSerials(kc.expDate, kc.issuer)
	if err != nil {
		return err
	}

	kc.known = data
	return nil
}

func (kc *KnownCertificates) Save() error {
	kc.mutex.Lock()
	defer kc.mutex.Unlock()

	err := kc.backend.StoreIssuerKnownSerials(kc.expDate, kc.issuer, kc.known)
	if err != nil {
		glog.Errorf("Error writing known certificates %s: %s", kc.id(), err)
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
		glog.V(3).Infof("[%s] Certificate already known: %s (pos=%d)", kc.id(), aSerial.Text(10), idx)
		return false, nil
	}

	// Non-allocating insert, see https://github.com/golang/go/wiki/SliceTricks
	glog.V(3).Infof("[%s] Certificate unknown: %s (pos=%d)", kc.id(), aSerial.Text(10), idx)
	kc.known = append(kc.known, nil)
	copy(kc.known[idx+1:], kc.known[idx:])
	kc.known[idx] = aSerial
	return true, nil
}

// Merge, handling duplicates
func (kc *KnownCertificates) Merge(other *KnownCertificates) error {
	kc.mutex.Lock()
	defer kc.mutex.Unlock()

	left := kc.known
	right := other.known
	l, r := 0, 0

	size := len(left) + len(right)
	result := make([]*big.Int, size)

	for i := 0; i < size; {
		var chosen *big.Int
		if l > len(left)-1 && r <= len(right)-1 {
			chosen = right[r]
			r++
		} else if r > len(right)-1 && l <= len(left)-1 {
			chosen = left[l]
			l++
		} else if r > len(right)-1 && l > len(left)-1 {
			// Duplicates caused us to run off the end, keep the relevant slice
			kc.known = result[:i]
			return nil
		} else if left[l].Cmp(right[r]) < 0 {
			chosen = left[l]
			l++
		} else {
			chosen = right[r]
			r++
		}

		if i > 0 {
			cmp := chosen.Cmp(result[i-1])
			switch {
			case cmp < 0:
				return fmt.Errorf("Unsorted merge")
			case cmp == 0:
				// Don't increment index i or set a value
				continue
			}
		}

		result[i] = chosen
		i++
	}

	kc.known = result
	return nil
}

func (kc *KnownCertificates) IsSorted() bool {
	if len(kc.known) > 1 {
		for i := 1; i < len(kc.known); i++ {
			if kc.known[i].Cmp(kc.known[i-1]) < 0 {
				return false
			}
		}
	}
	return true
}

func (kc *KnownCertificates) Known() []*big.Int {
	return kc.known[:]
}
