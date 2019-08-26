package storage

import (
	"encoding/base64"
	"fmt"
	"math/big"
	"time"

	"github.com/google/certificate-transparency-go/x509"
)

type CertificateLog struct {
	LogID         int       `db:"logID, primarykey, autoincrement"` // Log Identifier (FK to CertificateLog)
	URL           string    `db:"url"`                              // URL to the log
	MaxEntry      uint64    `db:"maxEntry"`                         // The most recent entryID logged
	LastEntryTime time.Time `db:"lastEntryTime"`                    // Date when we completed the last update
}

func (o *CertificateLog) String() string {
	return fmt.Sprintf("LogID=%d MaxEntry=%d, LastEntryTime=%s, URL=%s", o.LogID, o.MaxEntry, o.LastEntryTime, o.URL)
}

type DocumentType int

type StorageBackend interface {
	MarkDirty(id string) error

	StoreCertificatePEM(spki SPKI, expDate string, issuer string, b []byte) error
	StoreLogState(logURL string, log *CertificateLog) error
	StoreIssuerMetadata(expDate string, issuer string, data *Metadata) error
	StoreIssuerKnownSerials(expDate string, issuer string, serials []*big.Int) error

	LoadCertificatePEM(spki SPKI, expDate string, issuer string) ([]byte, error)
	LoadLogState(logURL string) (*CertificateLog, error)
	LoadIssuerMetadata(expDate string, issuer string) (*Metadata, error)
	LoadIssuerKnownSerials(expDate string, issuer string) ([]*big.Int, error)

	ListExpirationDates(aNotBefore time.Time) ([]string, error)
	ListIssuersForExpirationDate(expDate string) ([]string, error) // maybe return []AKI?
}

type CertDatabase interface {
	Cleanup() error
	SaveLogState(aLogObj *CertificateLog) error
	GetLogState(url string) (*CertificateLog, error)
	Store(aCert *x509.Certificate, aURL string) error
	ListExpirationDates(aNotBefore time.Time) ([]string, error)
	ListIssuersForExpirationDate(expDate string) ([]string, error)
	ReconstructIssuerMetadata(expDate string, issuer string) error
}

type AKI struct {
	aki []byte
}

func (o AKI) ID() string {
	return base64.URLEncoding.EncodeToString(o.aki)
}

type SPKI struct {
	spki []byte
}

func (o SPKI) ID() string {
	return base64.URLEncoding.EncodeToString(o.spki)
}
