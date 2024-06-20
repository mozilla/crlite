package storage

import (
	"context"
	"encoding/json"

	"github.com/mozilla/crlite/go"
)

type MockBackend struct {
	store map[string][]byte
}

func NewMockBackend() *MockBackend {
	return &MockBackend{
		store: make(map[string][]byte),
	}
}

func (db *MockBackend) StoreKnownCertificateList(_ context.Context, issuer types.Issuer,
	serials []types.Serial) error {
	encoded, err := json.Marshal(serials)
	if err != nil {
		return err
	}

	db.store[issuer.ID()] = encoded
	return nil
}

func (db *MockBackend) StoreRevokedCertificateList(_ context.Context, issuer types.Issuer,
	serials []types.SerialAndReason) error {
	encoded, err := json.Marshal(serials)
	if err != nil {
		return err
	}

	db.store[issuer.ID()] = encoded
	return nil
}
