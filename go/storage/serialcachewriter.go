package storage

import (
	"fmt"
	"strings"

	"github.com/golang/glog"
	"github.com/mozilla/crlite/go"
)

const kSerials = "serials"

type SerialCacheWriter struct {
	expDate   types.ExpDate
	issuer    types.Issuer
	cache     RemoteCache
	expirySet bool
}

func NewSerialCacheWriter(aExpDate types.ExpDate, aIssuer types.Issuer, aCache RemoteCache) *SerialCacheWriter {
	return &SerialCacheWriter{
		expDate:   aExpDate,
		issuer:    aIssuer,
		cache:     aCache,
		expirySet: false,
	}
}

func (kc *SerialCacheWriter) id(params ...string) string {
	return fmt.Sprintf("%s%s::%s", kc.expDate.ID(), strings.Join(params, ""), kc.issuer.ID())
}

func (kc *SerialCacheWriter) serialId(params ...string) string {
	return fmt.Sprintf("%s::%s", kSerials, kc.id(params...))
}

// Returns true if this serial was unknown. Subsequent calls with the same serial
// will return false, as it will be known then.
func (kc *SerialCacheWriter) Insert(aSerial types.Serial) (bool, error) {
	result, err := kc.cache.SetInsert(kc.serialId(), aSerial.BinaryString())
	if err != nil {
		return false, err
	}

	if !kc.expirySet {
		kc.setExpiryFlag()
		kc.expirySet = true
	}

	if result {
		glog.V(3).Infof("[%s] Certificate unknown: %s", kc.id(), aSerial)
	} else {
		glog.V(3).Infof("[%s] Certificate already known: %s", kc.id(), aSerial)
	}
	return result, nil
}

func (kc *SerialCacheWriter) Remove(aSerial types.Serial) (bool, error) {
	// Removing an element of a set may leave the set empty. Redis
	// automatically deletes empty sets, so assume that we need to reset
	// the ExpireAt time for this set on the next Insert call.
	kc.expirySet = false
	return kc.cache.SetRemove(kc.serialId(), aSerial.BinaryString())
}

func (kc *SerialCacheWriter) Count() int64 {
	count, err := kc.cache.SetCardinality(kc.serialId())
	if err != nil {
		glog.Errorf("Couldn't determine count of %s, now at %d: %s", kc.id(), count, err)
	}
	return int64(count)
}

func (kc *SerialCacheWriter) Contains(aSerial types.Serial) (bool, error) {
	return kc.cache.SetContains(kc.serialId(), aSerial.BinaryString())
}

func (kc *SerialCacheWriter) List() []types.Serial {
	// Redis' scan methods regularly provide duplicates. The duplication
	// happens at this level, pulling from SetToChan, so we make a hash-set
	// here to de-duplicate when the memory impacts are the most minimal.
	serials := make(map[string]struct{})
	var count int

	strChan := make(chan string)
	go func() {
		err := kc.cache.SetToChan(kc.serialId(), strChan)
		if err != nil {
			glog.Fatalf("Error obtaining list of known certificates: %v", err)
		}
	}()

	for str := range strChan {
		serials[str] = struct{}{}
		count += 1
	}

	serialList := make([]types.Serial, 0, count)
	for str := range serials {
		bs, err := types.NewSerialFromBinaryString(str)
		if err != nil {
			glog.Errorf("Failed to populate serial str=[%s] %v", str, err)
			continue
		}
		serialList = append(serialList, bs)
	}

	return serialList
}

func (kc *SerialCacheWriter) setExpiryFlag() {
	expireTime := kc.expDate.ExpireTime()

	if err := kc.cache.ExpireAt(kc.serialId(), expireTime); err != nil {
		glog.Errorf("Couldn't set expiration time %v for serials %s: %v", expireTime, kc.id(), err)
	}
}
