package storage

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/url"
	"time"

	"github.com/google/certificate-transparency-go/x509"
)

type CertificateLog struct {
	ShortURL      string    `db:"url"`           // URL to the log
	MaxEntry      int64     `db:"maxEntry"`      // The most recent entryID logged
	LastEntryTime time.Time `db:"lastEntryTime"` // Date when we completed the last update
}

func (o *CertificateLog) String() string {
	return fmt.Sprintf("[%s] MaxEntry=%d, LastEntryTime=%s", o.ShortURL, o.MaxEntry, o.LastEntryTime)
}

type DocumentType int

type StorageBackend interface {
	MarkDirty(id string) error

	StoreCertificatePEM(spki SPKI, expDate string, issuer string, b []byte) error
	StoreLogState(log *CertificateLog) error
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
	GetLogState(url *url.URL) (*CertificateLog, error)
	Store(aCert *x509.Certificate, aURL string) error
	ListExpirationDates(aNotBefore time.Time) ([]string, error)
	ListIssuersForExpirationDate(expDate string) ([]string, error)
	ReconstructIssuerMetadata(expDate string, issuer string) error
}

type AKI struct {
	aki       []byte
	rawIssuer []byte
}

func NewIssuer(aCert *x509.Certificate) *AKI {
	obj := &AKI{
		aki:       aCert.AuthorityKeyId,
		rawIssuer: aCert.RawIssuer,
	}
	return obj
}

func (o AKI) ID() string {
	if len(o.aki) == 0 {
		digest := sha256.Sum256(o.rawIssuer)
		return fmt.Sprintf("issuerHash-%s", base64.URLEncoding.EncodeToString(digest[:]))
	}
	return base64.URLEncoding.EncodeToString(o.aki)
}

type SPKI struct {
	spki []byte
}

func (o SPKI) ID() string {
	return base64.URLEncoding.EncodeToString(o.spki)
}
