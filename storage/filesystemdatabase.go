package storage

import (
	"crypto/sha1"
	"encoding/pem"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/bluele/gcache"
	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/x509"
)

const (
	kExpirationFormat = "2006-01-02"
)

type CacheEntry struct {
	mutex   *sync.Mutex
	expDate string
	issuer  Issuer
	known   *KnownCertificates
	meta    *IssuerMetadata
	backend StorageBackend
}

func NewCacheEntry(aExpDate string, aIssuerStr string, aBackend StorageBackend) (*CacheEntry, error) {
	obj := CacheEntry{
		mutex:   &sync.Mutex{},
		expDate: aExpDate,
		issuer:  NewIssuerFromString(aIssuerStr),
		known:   nil,
		meta:    nil,
		backend: aBackend,
	}
	obj.load()

	return &obj, nil
}

func (ce *CacheEntry) load() {
	ce.known = NewKnownCertificates(ce.expDate, ce.issuer, ce.backend)
	err := ce.known.Load()
	if err != nil {
		glog.V(1).Infof("Creating new known certificates file for %s:%s", ce.expDate, ce.issuer.ID())
	}

	ce.meta = NewIssuerMetadata(ce.expDate, ce.issuer, ce.backend)
	err = ce.meta.Load()
	if err != nil {
		glog.V(1).Infof("Creating new issuer metadata file for %s:%s", ce.expDate, ce.issuer.ID())
	}
}

func (ce *CacheEntry) Close() error {
	ce.mutex.Lock()
	defer ce.mutex.Unlock()

	errKnown := ce.known.Save()
	errMeta := ce.meta.Save()
	if errMeta != nil || errKnown != nil {
		return fmt.Errorf("Error saving data: Known=%s Meta=%s", errKnown, errMeta)
	}

	return nil
}

type FilesystemDatabase struct {
	backend StorageBackend
	cache   gcache.Cache
}

type cacheId struct {
	expDate   string
	issuerStr string
}

func NewFilesystemDatabase(aCacheSize int, aBackend StorageBackend) (*FilesystemDatabase, error) {
	cache := gcache.New(aCacheSize).ARC().
		EvictedFunc(func(key, value interface{}) {
			err := value.(*CacheEntry).Close()
			glog.V(2).Infof("CACHE: closed datafile: %s [err=%s]", key, err)
		}).
		PurgeVisitorFunc(func(key, value interface{}) {
			err := value.(*CacheEntry).Close()
			glog.V(2).Infof("CACHE: shutdown closed datafile: %s [err=%s]", key, err)
		}).
		LoaderFunc(func(key interface{}) (interface{}, error) {
			glog.V(2).Infof("CACHE: loaded datafile: %s", key)

			cacheId := key.(cacheId)

			return NewCacheEntry(cacheId.expDate, cacheId.issuerStr, aBackend)
		}).Build()

	db := &FilesystemDatabase{
		backend: aBackend,
		cache:   cache,
	}

	return db, nil
}

func (db *FilesystemDatabase) ListExpirationDates(aNotBefore time.Time) ([]string, error) {
	return db.backend.ListExpirationDates(aNotBefore)
}

func (db *FilesystemDatabase) ListIssuersForExpirationDate(expDate string) ([]Issuer, error) {
	return db.backend.ListIssuersForExpirationDate(expDate)
}

func (db *FilesystemDatabase) ReconstructIssuerMetadata(expDate string, issuer Issuer) error {
	return fmt.Errorf("Disabled")
}

func (db *FilesystemDatabase) SaveLogState(aLogObj *CertificateLog) error {
	return db.backend.StoreLogState(aLogObj)
}

func (db *FilesystemDatabase) GetLogState(aUrl *url.URL) (*CertificateLog, error) {
	shortUrl := fmt.Sprintf("%s%s", aUrl.Host, aUrl.Path)
	return db.backend.LoadLogState(shortUrl)
}

func (db *FilesystemDatabase) markDirty(aExpiration *time.Time) error {
	subdirName := aExpiration.Format(kExpirationFormat)
	return db.backend.MarkDirty(subdirName)
}

func getSpki(aCert *x509.Certificate) SPKI {
	if len(aCert.SubjectKeyId) < 8 {
		digest := sha1.Sum(aCert.RawSubjectPublicKeyInfo)

		glog.V(2).Infof("[issuer: %s] SPKI is short: %v, using %v instead.", aCert.Issuer.String(), aCert.SubjectKeyId, digest[0:])
		return SPKI{digest[0:]}
	}

	return SPKI{aCert.SubjectKeyId}
}

// Caller must obey the CacheEntry semantics
func (db *FilesystemDatabase) fetch(expDate string, issuer Issuer) (*CacheEntry, error) {
	obj, err := db.cache.Get(cacheId{expDate, issuer.ID()})
	if err != nil {
		return nil, err
	}

	ce := obj.(*CacheEntry)
	return ce, nil
}

func (db *FilesystemDatabase) Store(aCert *x509.Certificate, aLogURL string) error {
	spki := getSpki(aCert)
	expDate := aCert.NotAfter.Format(kExpirationFormat)
	issuer := NewIssuer(aCert)

	headers := make(map[string]string)
	headers["Log"] = aLogURL
	headers["Recorded-at"] = time.Now().Format(time.RFC3339)
	pemblock := pem.Block{
		Type:    "CERTIFICATE",
		Headers: headers,
		Bytes:   aCert.Raw,
	}

	ce, err := db.fetch(expDate, issuer)
	if err != nil {
		panic(err)
	}

	certWasUnknown, err := ce.known.WasUnknown(aCert.SerialNumber)
	if err != nil {
		return err
	}

	if certWasUnknown {
		ce.mutex.Lock()
		ce.meta.Accumulate(aCert)
		err = db.backend.StoreCertificatePEM(spki, expDate, issuer, pem.EncodeToMemory(&pemblock))
		ce.mutex.Unlock()

		if err != nil {
			return err
		}
	}

	// Mark the directory dirty
	err = db.markDirty(&aCert.NotAfter)
	if err != nil {
		return err
	}

	return nil
}

func (db *FilesystemDatabase) Cleanup() error {
	db.cache.Purge()
	return nil
}
