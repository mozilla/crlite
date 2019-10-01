package storage

import (
	"fmt"

	"github.com/golang/glog"
)

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
	result, err := kc.cache.SortedInsert(kc.id(), aSerial)
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
	serials, err := kc.cache.SortedList(kc.id())
	if err != nil {
		glog.Fatalf("Error obtaining list of known certificates: %v", err)
	}
	return serials
}
