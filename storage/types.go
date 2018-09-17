package storage

import (
	"fmt"
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
	return fmt.Sprintf("[%d] %s MaxEntry=%d, LastEntryTime=%s", o.LogID, o.URL, o.MaxEntry, o.LastEntryTime)
}

type CertDatabase interface {
	Cleanup() error
	SaveLogState(aLogObj *CertificateLog) error
	GetLogState(url string) (*CertificateLog, error)
	Store(aCert *x509.Certificate, aURL string) error
}
