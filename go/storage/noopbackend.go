package storage

import (
	"context"
	"fmt"

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

func (db *NoopBackend) StoreKnownCertificateList(_ context.Context, _ types.Issuer,
	_ []types.Serial) error {
	return nil
}
