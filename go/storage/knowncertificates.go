package storage

import (
	"fmt"
	"strings"

	"github.com/golang/glog"
)

const kSerials = "serials"

type KnownCertificates struct {
	expDate   ExpDate
	issuer    Issuer
	cache     RemoteCache
	expirySet bool
}

func NewKnownCertificates(aExpDate ExpDate, aIssuer Issuer, aCache RemoteCache) *KnownCertificates {
	return &KnownCertificates{
		expDate:   aExpDate,
		issuer:    aIssuer,
		cache:     aCache,
		expirySet: false,
	}
}

func (kc *KnownCertificates) id(params ...string) string {
	return fmt.Sprintf("%s%s::%s", kc.expDate.ID(), strings.Join(params, ""), kc.issuer.ID())
}

func (kc *KnownCertificates) serialId(params ...string) string {
	return fmt.Sprintf("%s::%s", kSerials, kc.id(params...))
}

// Returns true if this serial was unknown. Subsequent calls with the same serial
// will return false, as it will be known then.
func (kc *KnownCertificates) WasUnknown(aSerial Serial) (bool, error) {
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

func (kc *KnownCertificates) Count() int64 {
	count, err := kc.cache.SetCardinality(kc.serialId())
	if err != nil {
		glog.Errorf("Couldn't determine count of %s, now at %d: %s", kc.id(), count, err)
	}
	return int64(count)
}

func (kc *KnownCertificates) Known() []Serial {
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

	serialList := make([]Serial, 0, count)
	for str := range serials {
		bs, err := NewSerialFromBinaryString(str)
		if err != nil {
			glog.Errorf("Failed to populate serial str=[%s] %v", str, err)
			continue
		}
		serialList = append(serialList, bs)
	}

	return serialList
}

func (kc *KnownCertificates) setExpiryFlag() {
	expireTime := kc.expDate.ExpireTime()

	if err := kc.cache.ExpireAt(kc.serialId(), expireTime); err != nil {
		glog.Errorf("Couldn't set expiration time %v for serials %s: %v", expireTime, kc.id(), err)
	}
}
