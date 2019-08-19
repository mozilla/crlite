package storage

import (
	"encoding/base64"
	"fmt"
	"io"
	"path/filepath"
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

type StorageBackend interface {
	Store(id string, b []byte) error // TODO: Should take io.Reader
	Load(id string) ([]byte, error)
	List(path string, walkFn filepath.WalkFunc) error
	Writer(id string, append bool) (io.WriteCloser, error)
	ReadWriter(id string) (io.ReadWriteCloser, error)
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
