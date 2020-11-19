package storage

import (
	"context"
	"crypto/sha1"
	"encoding/pem"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bluele/gcache"
	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/x509"
)

type FilesystemDatabase struct {
	backend         StorageBackend
	extCache        RemoteCache
	knownCertsCache gcache.Cache
	metaMutex       *sync.RWMutex
	meta            map[string]*IssuerMetadata
}

func NewFilesystemDatabase(aBackend StorageBackend, aExtCache RemoteCache) (*FilesystemDatabase,
	error) {
	db := &FilesystemDatabase{
		backend:         aBackend,
		extCache:        aExtCache,
		knownCertsCache: gcache.New(8 * 1024).ARC().Build(),
		metaMutex:       &sync.RWMutex{},
		meta:            make(map[string]*IssuerMetadata),
	}

	return db, nil
}

func (db *FilesystemDatabase) GetIssuerMetadata(aIssuer Issuer) *IssuerMetadata {
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

func (db *FilesystemDatabase) GetIssuerAndDatesFromCache() ([]IssuerDate, error) {
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

func (db *FilesystemDatabase) ListExpirationDates(aNotBefore time.Time) ([]ExpDate, error) {
	return db.backend.ListExpirationDates(context.Background(), aNotBefore)
}

func (db *FilesystemDatabase) ListIssuersForExpirationDate(expDate ExpDate) ([]Issuer, error) {
	return db.backend.ListIssuersForExpirationDate(context.Background(), expDate)
}

func (db *FilesystemDatabase) SaveLogState(aLogObj *CertificateLog) error {
	ctx, ctxCancel := context.WithCancel(context.Background())
	defer ctxCancel()
	err := db.extCache.StoreLogState(aLogObj)
	if err != nil {
		glog.Warningf("Couldn't store log state for %s: %s", aLogObj, err)
	}
	return db.backend.StoreLogState(ctx, aLogObj)
}

func (db *FilesystemDatabase) GetLogState(aUrl *url.URL) (*CertificateLog, error) {
	ctx, ctxCancel := context.WithCancel(context.Background())
	defer ctxCancel()
	shortUrl := fmt.Sprintf("%s%s", aUrl.Host, aUrl.Path)

	log, cacheErr := db.extCache.LoadLogState(shortUrl)
	if log != nil {
		return log, cacheErr
	}

	log, backendErr := db.backend.LoadLogState(ctx, shortUrl)
	if log != nil {
		return log, backendErr
	}

	glog.Warningf("Allocating brand new log for %+v, cache err=%v, backend err=%v", shortUrl, cacheErr, backendErr)
	return &CertificateLog{
		ShortURL: shortUrl,
	}, nil
}

func (db *FilesystemDatabase) markDirty(aExpiration *time.Time) error {
	subdirName := aExpiration.Format(kExpirationFormat)
	return db.backend.MarkDirty(subdirName)
}

func getSpki(aCert *x509.Certificate) SPKI {
	if len(aCert.SubjectKeyId) < 8 {
		digest := sha1.Sum(aCert.RawSubjectPublicKeyInfo)

		glog.V(2).Infof("[issuer: %s] SPKI is short: %v, using %v instead.",
			aCert.Issuer.String(), aCert.SubjectKeyId, digest[0:])
		return SPKI{digest[0:]}
	}

	return SPKI{aCert.SubjectKeyId}
}

func (db *FilesystemDatabase) Store(aCert *x509.Certificate, aIssuer *x509.Certificate,
	aLogURL string, aEntryId int64) error {
	expDate := NewExpDateFromTime(aCert.NotAfter)
	issuer := NewIssuer(aIssuer)
	knownCerts := db.GetKnownCertificates(expDate, issuer)

	ctx, ctxCancel := context.WithCancel(context.Background())
	defer ctxCancel()

	headers := make(map[string]string)
	headers["Log"] = aLogURL
	headers["Recorded-at"] = time.Now().Format(time.RFC3339)
	headers["Entry-id"] = strconv.FormatInt(aEntryId, 10)
	pemblock := pem.Block{
		Type:    "CERTIFICATE",
		Headers: headers,
		Bytes:   aCert.Raw,
	}

	serialNum := NewSerial(aCert)

	certWasUnknown, err := knownCerts.WasUnknown(serialNum)
	if err != nil {
		return err
	}

	if certWasUnknown {
		issuerDateSeenBefore, err := db.GetIssuerMetadata(issuer).Accumulate(aCert)
		if err != nil {
			return err
		}
		if !issuerDateSeenBefore {
			// if the issuer/expdate was unknown in the cache
			errAlloc := db.backend.AllocateExpDateAndIssuer(ctx, expDate, issuer)
			if errAlloc != nil {
				return errAlloc
			}
		}

		errStore := db.backend.StoreCertificatePEM(ctx, serialNum, expDate, issuer,
			pem.EncodeToMemory(&pemblock))
		if errStore != nil {
			return errStore
		}
	}

	// Mark the directory dirty
	err = db.markDirty(&aCert.NotAfter)
	if err != nil {
		return err
	}

	return nil
}

func (db *FilesystemDatabase) GetKnownCertificates(aExpDate ExpDate,
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

func (db *FilesystemDatabase) Cleanup() error {
	// TODO: Remove
	return nil
}
