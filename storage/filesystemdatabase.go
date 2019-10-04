package storage

import (
	"crypto/sha1"
	"encoding/pem"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/bluele/gcache"
	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/x509"
)

type CacheEntry struct {
	known *KnownCertificates
	meta  *IssuerMetadata
}

func NewCacheEntry(aExpDate string, aIssuerStr string, aBackend StorageBackend, aCache RemoteCache) (*CacheEntry, error) {
	issuer := NewIssuerFromString(aIssuerStr)
	obj := CacheEntry{
		known: NewKnownCertificates(aExpDate, issuer, aCache),
		meta:  NewIssuerMetadata(aExpDate, issuer, aCache),
	}
	return &obj, nil
}

type FilesystemDatabase struct {
	backend  StorageBackend
	extCache RemoteCache
	cache    gcache.Cache
}

type cacheId struct {
	expDate   string
	issuerStr string
}

func NewFilesystemDatabase(aCacheSize int, aBackend StorageBackend, aExtCache RemoteCache) (*FilesystemDatabase, error) {
	cache := gcache.New(aCacheSize).ARC().
		LoaderFunc(func(key interface{}) (interface{}, error) {
			glog.V(2).Infof("CACHE: loaded datafile: %s", key)

			cacheId := key.(cacheId)

			return NewCacheEntry(cacheId.expDate, cacheId.issuerStr, aBackend, aExtCache)
		}).Build()

	db := &FilesystemDatabase{
		backend:  aBackend,
		cache:    cache,
		extCache: aExtCache,
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
	ce, err := db.fetch(expDate, issuer)
	if err != nil {
		glog.Fatalf("Couldn't retrieve from cache: %v", err)
	}

	serials, err := db.backend.ListSerialsForExpirationDateAndIssuer(expDate, issuer)
	if err != nil {
		return err
	}
	for _, serialNum := range serials {
		certWasUnknown, err := ce.known.WasUnknown(serialNum)
		if err != nil {
			return err
		}

		if certWasUnknown {
			pemBytes, err := db.backend.LoadCertificatePEM(serialNum, expDate, issuer)
			if err != nil {
				return err
			}
			block, rest := pem.Decode(pemBytes)
			if len(rest) > 0 {
				return fmt.Errorf("PEM data for %s %s %s had extra bytes: %+v", serialNum, expDate, issuer.ID(), rest)
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return err
			}
			issuerSeenBefore, err := ce.meta.Accumulate(cert)
			if err != nil {
				return err
			}

			if !issuerSeenBefore {
				ce.meta.SetExpiryFlag()
				ce.known.SetExpiryFlag()
			}
		}
	}
	return nil
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

func (db *FilesystemDatabase) Store(aCert *x509.Certificate, aIssuer *x509.Certificate, aLogURL string, aEntryId int64) error {
	expDate := aCert.NotAfter.Format(kExpirationFormat)
	issuer := NewIssuer(aIssuer)

	headers := make(map[string]string)
	headers["Log"] = aLogURL
	headers["Recorded-at"] = time.Now().Format(time.RFC3339)
	headers["Entry-id"] = strconv.FormatInt(aEntryId, 10)
	pemblock := pem.Block{
		Type:    "CERTIFICATE",
		Headers: headers,
		Bytes:   aCert.Raw,
	}

	ce, err := db.fetch(expDate, issuer)
	if err != nil {
		glog.Fatalf("Couldn't retrieve from cache: %v", err)
	}

	serialNum := NewSerial(aCert)

	certWasUnknown, err := ce.known.WasUnknown(serialNum)
	if err != nil {
		return err
	}

	if certWasUnknown {
		issuerSeenBefore, err := ce.meta.Accumulate(aCert)
		if err != nil {
			return err
		}
		if !issuerSeenBefore {
			// if the issuer/expdate was unknown in the cache
			errAlloc := db.backend.AllocateExpDateAndIssuer(expDate, issuer)
			if errAlloc != nil {
				return errAlloc
			}
			ce.meta.SetExpiryFlag()
			ce.known.SetExpiryFlag()
		}

		errStore := db.backend.StoreCertificatePEM(serialNum, expDate, issuer, pem.EncodeToMemory(&pemblock))
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

func (db *FilesystemDatabase) GetKnownCertificates(aExpDate string, aIssuer Issuer) (*KnownCertificates, error) {
	kc := NewKnownCertificates(aExpDate, aIssuer, db.extCache)
	return kc, nil
}

func (db *FilesystemDatabase) GetIssuerMetadata(aExpDate string, aIssuer Issuer) (*IssuerMetadata, error) {
	im := NewIssuerMetadata(aExpDate, aIssuer, db.extCache)
	return im, nil
}

func (db *FilesystemDatabase) Cleanup() error {
	db.cache.Purge()
	return nil
}
