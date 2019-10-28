package storage

import (
	"context"
	"crypto/sha1"
	"encoding/pem"
	"fmt"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/armon/go-metrics"
	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/x509"
)

type FilesystemDatabase struct {
	backend   StorageBackend
	extCache  RemoteCache
	metaMutex *sync.RWMutex
	meta      map[string]*IssuerMetadata
}

func NewFilesystemDatabase(aCacheSize int, aBackend StorageBackend, aExtCache RemoteCache) (*FilesystemDatabase, error) {
	db := &FilesystemDatabase{
		backend:   aBackend,
		extCache:  aExtCache,
		metaMutex: &sync.RWMutex{},
		meta:      make(map[string]*IssuerMetadata),
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

func (db *FilesystemDatabase) ListExpirationDates(aNotBefore time.Time) ([]string, error) {
	return db.backend.ListExpirationDates(context.Background(), aNotBefore)
}

func (db *FilesystemDatabase) ListIssuersForExpirationDate(expDate string) ([]Issuer, error) {
	return db.backend.ListIssuersForExpirationDate(context.Background(), expDate)
}

func (db *FilesystemDatabase) ReconstructIssuerMetadata(expDate string, issuer Issuer) error {
	knownCerts := db.GetKnownCertificates(expDate, issuer)

	startTime := time.Now()
	ctx, ctxCancel := context.WithCancel(context.Background())
	defer ctxCancel()
	serialChan, err := db.backend.StreamSerialsForExpirationDateAndIssuer(ctx, expDate, issuer)
	if err != nil {
		return err
	}
	metrics.MeasureSince([]string{"ReconstructIssuerMetadata", "ListSerials"}, startTime)

	for serialNum := range serialChan {
		certWasUnknown, err := knownCerts.WasUnknown(serialNum)
		if err != nil {
			return fmt.Errorf("ReconstructIssuerMetadata Was Unknown %v", err)
		}

		if certWasUnknown {
			subCtx, subCancel := context.WithTimeout(ctx, 15*time.Minute)

			metrics.IncrCounter([]string{"ReconstructIssuerMetadata", "certWasUnknown"}, 1)

			pemTime := time.Now()
			pemBytes, err := db.backend.LoadCertificatePEM(subCtx, serialNum, expDate, issuer)
			if err != nil {
				subCancel()
				return fmt.Errorf("ReconstructIssuerMetadata error LoadCertificatePEM %v", err)
			}
			metrics.MeasureSince([]string{"ReconstructIssuerMetadata", "Load"}, pemTime)

			decodeTime := time.Now()
			block, rest := pem.Decode(pemBytes)
			if len(rest) > 0 {
				subCancel()
				return fmt.Errorf("PEM data for %s %s %s had extra bytes: %+v", serialNum, expDate, issuer.ID(), rest)
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				subCancel()
				metrics.IncrCounter([]string{"ReconstructIssuerMetadata", "certParseError"}, 1)
				return fmt.Errorf("ReconstructIssuerMetadata error ParseCertificate %v", err)
			}
			metrics.MeasureSince([]string{"ReconstructIssuerMetadata", "DecodeParse"}, decodeTime)

			redisTime := time.Now()
			issuerSeenBefore, err := db.GetIssuerMetadata(issuer).Accumulate(cert)
			if err != nil {
				subCancel()
				return fmt.Errorf("ReconstructIssuerMetadata error Accumulate %v", err)
			}

			if !issuerSeenBefore {
				// if the issuer/expdate was unknown in the cache
				errAlloc := db.backend.AllocateExpDateAndIssuer(subCtx, expDate, issuer)
				if errAlloc != nil {
					subCancel()
					return fmt.Errorf("ReconstructIssuerMetadata error AllocateExpDateAndIssuer %v", errAlloc)
				}
				knownCerts.SetExpiryFlag()
			}

			metrics.MeasureSince([]string{"ReconstructIssuerMetadata", "CacheInsertion"}, redisTime)
			subCancel()
		} else {
			metrics.IncrCounter([]string{"ReconstructIssuerMetadata", "certWasKnown"}, 1)
		}
	}

	metrics.MeasureSince([]string{"ReconstructIssuerMetadata"}, startTime)
	return nil
}

func (db *FilesystemDatabase) SaveLogState(aLogObj *CertificateLog) error {
	ctx, ctxCancel := context.WithCancel(context.Background())
	defer ctxCancel()
	return db.backend.StoreLogState(ctx, aLogObj)
}

func (db *FilesystemDatabase) GetLogState(aUrl *url.URL) (*CertificateLog, error) {
	ctx, ctxCancel := context.WithCancel(context.Background())
	defer ctxCancel()
	shortUrl := fmt.Sprintf("%s%s", aUrl.Host, aUrl.Path)
	return db.backend.LoadLogState(ctx, shortUrl)
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

func (db *FilesystemDatabase) Store(aCert *x509.Certificate, aIssuer *x509.Certificate, aLogURL string, aEntryId int64) error {
	expDate := aCert.NotAfter.Format(kExpirationFormat)
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
		issuerSeenBefore, err := db.GetIssuerMetadata(issuer).Accumulate(aCert)
		if err != nil {
			return err
		}
		if !issuerSeenBefore {
			// if the issuer/expdate was unknown in the cache
			errAlloc := db.backend.AllocateExpDateAndIssuer(ctx, expDate, issuer)
			if errAlloc != nil {
				return errAlloc
			}
			knownCerts.SetExpiryFlag()
		}

		errStore := db.backend.StoreCertificatePEM(ctx, serialNum, expDate, issuer, pem.EncodeToMemory(&pemblock))
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

func (db *FilesystemDatabase) GetKnownCertificates(aExpDate string, aIssuer Issuer) *KnownCertificates {
	return NewKnownCertificates(aExpDate, aIssuer, db.extCache)
}

func (db *FilesystemDatabase) Cleanup() error {
	// TODO: Remove
	return nil
}
