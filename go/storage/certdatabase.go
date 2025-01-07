package storage

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/bluele/gcache"
	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/x509"

	"github.com/mozilla/crlite/go"
)

type CertDatabase struct {
	extCache           RemoteCache
	serialCacheWriters gcache.Cache
}

func NewCertDatabase(aExtCache RemoteCache) (CertDatabase, error) {
	db := CertDatabase{
		extCache:           aExtCache,
		serialCacheWriters: gcache.New(8 * 1024).ARC().Build(),
	}

	return db, nil
}

func (db *CertDatabase) GetCTLogsFromCache() ([]types.CTLogState, error) {
	return db.extCache.LoadAllLogStates()
}

func (db *CertDatabase) GetIssuerAndDatesFromCache() ([]types.IssuerDate, error) {
	issuerMap := make(map[string]types.IssuerDate)
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
			return []types.IssuerDate{}, fmt.Errorf("Unexpected key format: %s", entry)
		}

		issuer := types.NewIssuerFromString(parts[2])
		expDate, err := types.NewExpDate(parts[1])
		if err != nil {
			glog.Warningf("Couldn't parse expiration date %s: %s", entry, err)
			continue
		}

		_, ok := issuerMap[issuer.ID()]
		if !ok {
			issuerMap[issuer.ID()] = types.IssuerDate{
				Issuer:   issuer,
				ExpDates: make([]types.ExpDate, 0),
			}
		}

		tmp := issuerMap[issuer.ID()]
		tmp.ExpDates = append(tmp.ExpDates, expDate)
		issuerMap[issuer.ID()] = tmp
	}

	issuerList := make([]types.IssuerDate, 0, len(issuerMap))
	for _, v := range issuerMap {
		issuerList = append(issuerList, v)
	}
	return issuerList, nil
}

func (db *CertDatabase) Migrate(aLogData *types.CTLogMetadata) error {
	return db.extCache.Migrate(aLogData)
}

func (db *CertDatabase) SaveLogState(aLogObj *types.CTLogState) error {
	return db.extCache.StoreLogState(aLogObj)
}

func (db *CertDatabase) GetLogState(aUrl *url.URL) (*types.CTLogState, error) {
	shortUrl := fmt.Sprintf("%s%s", aUrl.Host, strings.TrimRight(aUrl.Path, "/"))

	log, cacheErr := db.extCache.LoadLogState(shortUrl)
	if log != nil {
		return log, cacheErr
	}

	glog.Warningf("Allocating brand new log for %+v, cache err=%v", shortUrl, cacheErr)
	return &types.CTLogState{
		ShortURL: shortUrl,
	}, nil
}

func (db *CertDatabase) Store(aCert *x509.Certificate, aIssuer *x509.Certificate,
	aLogURL string, aEntryId int64) error {
	expDate := types.NewExpDateFromTime(aCert.NotAfter)
	issuer := types.NewIssuer(aIssuer)
	serialWriter := db.GetSerialCacheWriter(expDate, issuer)

	serial := types.NewSerial(aCert)

	_, err := serialWriter.Insert(serial)
	if err != nil {
		return err
	}

	return nil
}

func (db *CertDatabase) GetSerialCacheWriter(aExpDate types.ExpDate,
	aIssuer types.Issuer) *SerialCacheWriter {
	var kc *SerialCacheWriter

	id := aExpDate.ID() + aIssuer.ID()

	cacheObj, err := db.serialCacheWriters.GetIFPresent(id)
	if err != nil {
		if err == gcache.KeyNotFoundError {
			kc = NewSerialCacheWriter(aExpDate, aIssuer, db.extCache)
			err = db.serialCacheWriters.Set(id, kc)
			if err != nil {
				glog.Fatalf("Couldn't set into the cache expDate=%s issuer=%s from cache: %s",
					aExpDate, aIssuer.ID(), err)
			}
		} else {
			glog.Fatalf("Couldn't load expDate=%s issuer=%s from cache: %s",
				aExpDate, aIssuer.ID(), err)
		}
	} else {
		kc = cacheObj.(*SerialCacheWriter)
	}

	if kc == nil {
		panic("kc is null")
	}
	return kc
}
