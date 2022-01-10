package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/mozilla/crlite/go"
)

type NoopBackend struct {
}

func NewNoopBackend() *NoopBackend {
	return &NoopBackend{}
}

func (db *NoopBackend) noopLoadError() error {
	return fmt.Errorf("Unable to load from the NoopBackend.")
}

func (db *NoopBackend) MarkDirty(id string) error {
	return nil
}

func (db *NoopBackend) AllocateExpDateAndIssuer(_ context.Context, _ types.ExpDate,
	_ types.Issuer) error {
	return nil
}

func (db *NoopBackend) StoreCertificatePEM(_ context.Context, _ types.Serial, _ types.ExpDate,
	_ types.Issuer, _ []byte) error {
	return nil
}

func (db *NoopBackend) StoreLogState(_ context.Context, _ *CertificateLog) error {
	return nil
}

func (db *NoopBackend) StoreKnownCertificateList(_ context.Context, _ types.Issuer,
	_ []types.Serial) error {
	return nil
}

func (db *NoopBackend) LoadCertificatePEM(_ context.Context, _ types.Serial, _ types.ExpDate,
	_ types.Issuer) ([]byte, error) {
	return []byte{}, db.noopLoadError()
}

func (db *NoopBackend) LoadLogState(_ context.Context, _ string) (*CertificateLog, error) {
	return nil, db.noopLoadError()
}

func (db *NoopBackend) ListExpirationDates(_ context.Context, _ time.Time) ([]types.ExpDate, error) {
	return []types.ExpDate{}, db.noopLoadError()
}

func (db *NoopBackend) ListIssuersForExpirationDate(_ context.Context, _ types.ExpDate) ([]types.Issuer,
	error) {
	return []types.Issuer{}, db.noopLoadError()
}

func (db *NoopBackend) ListSerialsForExpirationDateAndIssuer(_ context.Context, _ types.ExpDate,
	issuer types.Issuer) ([]types.Serial, error) {
	return []types.Serial{}, db.noopLoadError()
}

func (db *NoopBackend) StreamSerialsForExpirationDateAndIssuer(_ context.Context, _ types.ExpDate,
	_ types.Issuer, _ <-chan struct{}, _ chan<- types.UniqueCertIdentifier) error {
	return db.noopLoadError()
}
