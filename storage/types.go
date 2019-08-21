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

type DocumentType int

const (
	TypeLogState                        = 1
	TypeIssuerMetadata     DocumentType = 2
	TypeIssuerKnownSerials DocumentType = 3
	TypeCertificatePEMList DocumentType = 4
	TypeBulk               DocumentType = 5
)

func (t DocumentType) String() string {
	names := [...]string{
		"Log State",
		"Issuer Metadata",
		"Issuer Known Serials",
		"Certificate PEM List",
		"Bulk",
	}

	if t < TypeLogState || t > TypeCertificatePEMList {
		return "Unknown"
	}
	return names[t]
}

type StorageBackend interface {
	MarkDirty(id string) error
	Store(docType DocumentType, id string, b []byte) error // TODO: Should take io.Reader
	Load(docType DocumentType, id string) ([]byte, error)
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
