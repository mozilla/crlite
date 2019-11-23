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

func (kc *KnownCertificates) allSerialIds() []string {
	ids := make([]string, 25)
	ids[0] = kc.serialId()
	for hour := 0; hour < 24; hour++ {
		ids[hour+1] = kc.serialId(fmt.Sprintf("-%02d", hour))
	}
	return ids
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
	var count int64
	for _, key := range kc.allSerialIds() {
		setLen, err := kc.cache.SetCardinality(key)
		if err != nil {
			glog.Errorf("Couldn't determine count of %s, now at %d: %s", kc.id(), count, err)
		}
		count += int64(setLen)
	}
	return count
}

func (kc *KnownCertificates) Known() []Serial {
	var serials []Serial
	for _, key := range kc.allSerialIds() {
		setLen, err := kc.cache.SetCardinality(key)
		if err != nil {
			// Not a fatal, as we can naively double serials (the default for append)
			// which could happen anyway in the rare event the set changes size during
			// iteration
			glog.Errorf("Error determining set length for %s: %s", key, err)
		}

		if cap(serials) < len(serials)+setLen {
			tmp := make([]Serial, len(serials), len(serials)+setLen)
			copy(tmp, serials)
			serials = tmp
		}

		strChan := make(chan string)
		go func() {
			err := kc.cache.SetToChan(key, strChan)
			if err != nil {
				glog.Fatalf("Error obtaining list of known certificates: %v", err)
			}
		}()

		for str := range strChan {
			bs, err := NewSerialFromBinaryString(str)
			if err != nil {
				glog.Errorf("Failed to populate serial str=[%s] %v", str, err)
				continue
			}

			serials = append(serials, bs)
		}
	}

	return serials
}

func (kc *KnownCertificates) setExpiryFlag() {
	expireTime := kc.expDate.ExpireTime()

	if err := kc.cache.ExpireAt(kc.serialId(), expireTime); err != nil {
		glog.Errorf("Couldn't set expiration time %v for serials %s: %v", expireTime, kc.id(), err)
	}
}
