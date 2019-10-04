package storage

import (
	"fmt"
	"time"

	"github.com/golang/glog"
)

const kSerials = "serials"

type KnownCertificates struct {
	expDate string
	issuer  Issuer
	cache   RemoteCache
}

func NewKnownCertificates(aExpDate string, aIssuer Issuer, aCache RemoteCache) *KnownCertificates {
	return &KnownCertificates{
		expDate: aExpDate,
		issuer:  aIssuer,
		cache:   aCache,
	}
}

func (kc *KnownCertificates) id() string {
	return fmt.Sprintf("%s::%s", kc.expDate, kc.issuer.ID())
}

// Returns true if this serial was unknown. Subsequent calls with the same serial
// will return false, as it will be known then.
func (kc *KnownCertificates) WasUnknown(aSerial Serial) (bool, error) {
	result, err := kc.cache.SortedInsert(fmt.Sprintf("%s::%s", kSerials, kc.id()), aSerial.String())
	if err != nil {
		return false, err
	}

	if result {
		glog.V(3).Infof("[%s] Certificate unknown: %s", kc.id(), aSerial)
	} else {
		glog.V(3).Infof("[%s] Certificate already known: %s", kc.id(), aSerial)
	}
	return result, nil
}

func (kc *KnownCertificates) Known() []Serial {
	strList, err := kc.cache.SortedList(fmt.Sprintf("%s::%s", kSerials, kc.id()))
	if err != nil {
		glog.Fatalf("Error obtaining list of known certificates: %v", err)
	}
	serials := make([]Serial, len(strList))
	for i, str := range strList {
		serials[i] = NewSerialFromHex(str)
	}
	return serials
}

func (kc *KnownCertificates) SetExpiryFlag() {
	expireTime, timeErr := time.ParseInLocation(kExpirationFormat, kc.expDate, time.UTC)
	if timeErr != nil {
		glog.Errorf("Couldn't parse expiration time %s: %v", kc.expDate, timeErr)
		return
	}

	if err := kc.cache.ExpireAt(fmt.Sprintf("%s::%s", kSerials, kc.id()), expireTime); err != nil {
		glog.Errorf("Couldn't set expiration time %v for serials %s: %v", expireTime, kc.id(), err)
	}
}
