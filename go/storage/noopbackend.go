package storage

import (
	"context"
	"fmt"
	"time"
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

func (db *NoopBackend) AllocateExpDateAndIssuer(_ context.Context, _ ExpDate,
	_ Issuer) error {
	return nil
}

func (db *NoopBackend) StoreCertificatePEM(_ context.Context, _ Serial, _ ExpDate,
	_ Issuer, _ []byte) error {
	return nil
}

func (db *NoopBackend) StoreLogState(_ context.Context, _ *CertificateLog) error {
	return nil
}

func (db *NoopBackend) StoreKnownCertificateList(_ context.Context, _ Issuer,
	_ []Serial) error {
	return nil
}

func (db *NoopBackend) LoadCertificatePEM(_ context.Context, _ Serial, _ ExpDate,
	_ Issuer) ([]byte, error) {
	return []byte{}, db.noopLoadError()
}

func (db *NoopBackend) LoadLogState(_ context.Context, _ string) (*CertificateLog, error) {
	return nil, db.noopLoadError()
}

func (db *NoopBackend) ListExpirationDates(_ context.Context, _ time.Time) ([]ExpDate, error) {
	return []ExpDate{}, db.noopLoadError()
}

func (db *NoopBackend) ListIssuersForExpirationDate(_ context.Context, _ ExpDate) ([]Issuer,
	error) {
	return []Issuer{}, db.noopLoadError()
}

func (db *NoopBackend) ListSerialsForExpirationDateAndIssuer(_ context.Context, _ ExpDate,
	issuer Issuer) ([]Serial, error) {
	return []Serial{}, db.noopLoadError()
}

func (db *NoopBackend) StreamSerialsForExpirationDateAndIssuer(_ context.Context, _ ExpDate,
	_ Issuer, _ <-chan struct{}, _ chan<- UniqueCertIdentifier) error {
	return db.noopLoadError()
}
