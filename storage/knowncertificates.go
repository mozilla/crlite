package storage

import (
	"fmt"
	"time"

	"github.com/golang/glog"
)

const kSerials = "serials"

type KnownCertificates struct {
	expDate   string
	issuer    Issuer
	cache     RemoteCache
	expirySet bool
}

func NewKnownCertificates(aExpDate string, aIssuer Issuer, aCache RemoteCache) *KnownCertificates {
	return &KnownCertificates{
		expDate:   aExpDate,
		issuer:    aIssuer,
		cache:     aCache,
		expirySet: false,
	}
}

func (kc *KnownCertificates) id() string {
	return fmt.Sprintf("%s::%s", kc.expDate, kc.issuer.ID())
}

func (kc *KnownCertificates) serialId() string {
	return fmt.Sprintf("%s::%s", kSerials, kc.id())
}

// Returns true if this serial was unknown. Subsequent calls with the same serial
// will return false, as it will be known then.
func (kc *KnownCertificates) WasUnknown(aSerial Serial) (bool, error) {
	result, err := kc.cache.SortedInsert(kc.serialId(), aSerial.Ascii85())
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

func (kc *KnownCertificates) Known() []Serial {
	strList, err := kc.cache.SortedList(kc.serialId())
	if err != nil {
		glog.Fatalf("Error obtaining list of known certificates: %v", err)
	}
	serials := make([]Serial, len(strList))
	for i, str := range strList {
		serials[i], err = NewSerialFromAscii85(str)
		if err != nil {
			glog.Errorf("Failed to populate serial idx %d str=[%s] %v", i, str, err)
		}
	}
	return serials
}

func (kc *KnownCertificates) setExpiryFlag() {
	expireTime, timeErr := time.ParseInLocation(kExpirationFormat, kc.expDate, time.UTC)
	if timeErr != nil {
		glog.Errorf("Couldn't parse expiration time %s: %v", kc.expDate, timeErr)
		return
	}

	if err := kc.cache.ExpireAt(kc.serialId(), expireTime); err != nil {
		glog.Errorf("Couldn't set expiration time %v for serials %s: %v", expireTime, kc.id(), err)
	}
}
