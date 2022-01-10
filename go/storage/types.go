package storage

import (
	"context"
	"time"

	"github.com/mozilla/crlite/go"
)

type StorageBackend interface {
	MarkDirty(id string) error

	StoreCertificatePEM(ctx context.Context, serial types.Serial, expDate types.ExpDate,
		issuer types.Issuer, b []byte) error
	StoreLogState(ctx context.Context, log *CertificateLog) error
	StoreKnownCertificateList(ctx context.Context, issuer types.Issuer,
		serials []types.Serial) error

	LoadCertificatePEM(ctx context.Context, serial types.Serial, expDate types.ExpDate,
		issuer types.Issuer) ([]byte, error)
	LoadLogState(ctx context.Context, logURL string) (*CertificateLog, error)
	LoadAllLogStates(ctx context.Context) ([]CertificateLog, error)

	AllocateExpDateAndIssuer(ctx context.Context, expDate types.ExpDate, issuer types.Issuer) error

	ListExpirationDates(ctx context.Context, aNotBefore time.Time) ([]types.ExpDate, error)
	ListIssuersForExpirationDate(ctx context.Context, expDate types.ExpDate) ([]types.Issuer, error)

	ListSerialsForExpirationDateAndIssuer(ctx context.Context, expDate types.ExpDate,
		issuer types.Issuer) ([]types.Serial, error)
	StreamSerialsForExpirationDateAndIssuer(ctx context.Context, expDate types.ExpDate,
		issuer types.Issuer, quitChan <-chan struct{}, stream chan<- types.UniqueCertIdentifier) error
}

type RemoteCache interface {
	Exists(key string) (bool, error)
	SetInsert(key string, aEntry string) (bool, error)
	SetRemove(key string, entry string) (bool, error)
	SetContains(key string, aEntry string) (bool, error)
	SetList(key string) ([]string, error)
	SetToChan(key string, c chan<- string) error
	SetCardinality(key string) (int, error)
	ExpireAt(key string, aExpTime time.Time) error
	ExpireIn(key string, aDur time.Duration) error
	Queue(key string, identifier string) (int64, error)
	Pop(key string) (string, error)
	QueueLength(key string) (int64, error)
	BlockingPopCopy(key string, dest string, timeout time.Duration) (string, error)
	ListRemove(key string, value string) error
	TrySet(k string, v string, life time.Duration) (string, error)
	KeysToChan(pattern string, c chan<- string) error
	StoreLogState(aLogObj *CertificateLog) error
	LoadLogState(aLogUrl string) (*CertificateLog, error)
	LoadAllLogStates() ([]CertificateLog, error)
}
