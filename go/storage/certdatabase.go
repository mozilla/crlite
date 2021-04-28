package storage

import (
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/bluele/gcache"
	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/x509"
)

type CertDatabase struct {
	extCache        RemoteCache
	knownCertsCache gcache.Cache
	metaMutex       *sync.RWMutex
	meta            map[string]*IssuerMetadata
}

func NewCertDatabase(aExtCache RemoteCache) (CertDatabase, error) {
	db := CertDatabase{
		extCache:        aExtCache,
		knownCertsCache: gcache.New(8 * 1024).ARC().Build(),
		metaMutex:       &sync.RWMutex{},
		meta:            make(map[string]*IssuerMetadata),
	}

	return db, nil
}

func (db *CertDatabase) GetIssuerMetadata(aIssuer Issuer) *IssuerMetadata {
	db.metaMutex.RLock()

	im, ok := db.meta[aIssuer.ID()]
	if ok {
		db.metaMutex.RUnlock()
		return im
	}

	db.metaMutex.RUnlock()
	db.metaMutex.Lock()

	im = NewIssuerMetadata(aIssuer, db.extCache)
	db.meta[aIssuer.ID()] = im

	db.metaMutex.Unlock()
	return im
}

func (db *CertDatabase) GetIssuerAndDatesFromCache() ([]IssuerDate, error) {
	issuerMap := make(map[string]IssuerDate)
	allChan := make(chan string)
	go func() {
		err := db.extCache.KeysToChan("serials::*", allChan)
		if err != nil {
			glog.Fatalf("Couldn't list from cache")
		}
	}()

	for entry := range allChan {
		parts := strings.Split(entry, "::")
		if len(parts) != 3 {
			return []IssuerDate{}, fmt.Errorf("Unexpected key format: %s", entry)
		}

		issuer := NewIssuerFromString(parts[2])
		expDate, err := NewExpDate(parts[1])
		if err != nil {
			glog.Warningf("Couldn't parse expiration date %s: %s", entry, err)
			continue
		}

		_, ok := issuerMap[issuer.ID()]
		if !ok {
			issuerMap[issuer.ID()] = IssuerDate{
				Issuer:   issuer,
				ExpDates: make([]ExpDate, 0),
			}
		}

		tmp := issuerMap[issuer.ID()]
		tmp.ExpDates = append(tmp.ExpDates, expDate)
		issuerMap[issuer.ID()] = tmp
	}

	issuerList := make([]IssuerDate, 0, len(issuerMap))
	for _, v := range issuerMap {
		issuerList = append(issuerList, v)
	}
	return issuerList, nil
}

func (db *CertDatabase) SaveLogState(aLogObj *CertificateLog) error {
	return db.extCache.StoreLogState(aLogObj)
}

func (db *CertDatabase) GetLogState(aUrl *url.URL) (*CertificateLog, error) {
	shortUrl := fmt.Sprintf("%s%s", aUrl.Host, aUrl.Path)

	log, cacheErr := db.extCache.LoadLogState(shortUrl)
	if log != nil {
		return log, cacheErr
	}

	glog.Warningf("Allocating brand new log for %+v, cache err=%v", shortUrl, cacheErr)
	return &CertificateLog{
		ShortURL: shortUrl,
	}, nil
}

func (db *CertDatabase) Store(aCert *x509.Certificate, aIssuer *x509.Certificate,
	aLogURL string, aEntryId int64) error {
	expDate := NewExpDateFromTime(aCert.NotAfter)
	issuer := NewIssuer(aIssuer)
	knownCerts := db.GetKnownCertificates(expDate, issuer)

	serialNum := NewSerial(aCert)

	// WasUnknown stores the certificate if it was unknown.
	_, err := knownCerts.WasUnknown(serialNum)
	return err
}

func (db *CertDatabase) GetKnownCertificates(aExpDate ExpDate,
	aIssuer Issuer) *KnownCertificates {
	var kc *KnownCertificates

	id := aExpDate.ID() + aIssuer.ID()

	cacheObj, err := db.knownCertsCache.GetIFPresent(id)
	if err != nil {
		if err == gcache.KeyNotFoundError {
			kc = NewKnownCertificates(aExpDate, aIssuer, db.extCache)
			err = db.knownCertsCache.Set(id, kc)
			if err != nil {
				glog.Fatalf("Couldn't set into the cache expDate=%s issuer=%s from cache: %s",
					aExpDate, aIssuer.ID(), err)
			}
		} else {
			glog.Fatalf("Couldn't load expDate=%s issuer=%s from cache: %s",
				aExpDate, aIssuer.ID(), err)
		}
	} else {
		kc = cacheObj.(*KnownCertificates)
	}

	if kc == nil {
		panic("kc is null")
	}
	return kc
}
