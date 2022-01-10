package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/mozilla/crlite/go"
)

const (
	kExpirationFormat         = "2006-01-02"
	kExpirationFormatWithHour = "2006-01-02-15"
)

type MockBackend struct {
	expDateToIssuer          map[string][]types.Issuer
	expDateIssuerIDToSerials map[string][]types.Serial
	store                    map[string][]byte
}

func NewMockBackend() *MockBackend {
	return &MockBackend{
		expDateToIssuer:          make(map[string][]types.Issuer),
		expDateIssuerIDToSerials: make(map[string][]types.Serial),
		store:                    make(map[string][]byte),
	}
}

func (db *MockBackend) MarkDirty(id string) error {
	return nil
}

func (db *MockBackend) AllocateExpDateAndIssuer(_ context.Context, expDate types.ExpDate,
	issuer types.Issuer) error {
	issuers, ok := db.expDateToIssuer[expDate.ID()]
	if !ok {
		issuers = []types.Issuer{}
	}
	i := sort.Search(len(issuers), func(i int) bool {
		return strings.Compare(issuers[i].ID(), issuer.ID()) >= 0
	})
	if i < len(issuers) && issuers[i].ID() == issuer.ID() {
		// already noted
	} else {
		issuers = append(issuers, types.Issuer{})
		copy(issuers[i+1:], issuers[i:])
		issuers[i] = issuer
		db.expDateToIssuer[expDate.ID()] = issuers
	}
	return nil
}

func (db *MockBackend) StoreCertificatePEM(_ context.Context, serial types.Serial, expDate types.ExpDate,
	issuer types.Issuer, b []byte) error {
	db.store["pem"+expDate.ID()+issuer.ID()+serial.ID()] = b
	val, ok := db.expDateIssuerIDToSerials[expDate.ID()+issuer.ID()]
	if !ok {
		val = []types.Serial{}
	}
	db.expDateIssuerIDToSerials[expDate.ID()+issuer.ID()] = append(val, serial)
	return nil
}

func (db *MockBackend) StoreLogState(_ context.Context, log *CertificateLog) error {
	data, err := json.Marshal(log)
	if err != nil {
		return err
	}
	db.store["logstate"+log.ShortURL] = data
	return nil
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

func (db *MockBackend) LoadCertificatePEM(_ context.Context, serial types.Serial, expDate types.ExpDate,
	issuer types.Issuer) ([]byte, error) {
	data, ok := db.store["pem"+expDate.ID()+issuer.ID()+serial.ID()]
	if ok {
		return data, nil
	}
	return []byte{}, fmt.Errorf("Couldn't find")
}

func (db *MockBackend) LoadLogState(_ context.Context, logURL string) (*CertificateLog, error) {
	data, ok := db.store["logstate"+logURL]
	if ok {
		var log *CertificateLog
		err := json.Unmarshal(data, &log)
		return log, err
	}
	return &CertificateLog{
		ShortURL: logURL,
	}, nil
}

func (db *MockBackend) ListExpirationDates(_ context.Context, aNotBefore time.Time) ([]types.ExpDate, error) {
	dates := []types.ExpDate{}
	truncatedNotBefore := time.Date(aNotBefore.Year(), aNotBefore.Month(),
		aNotBefore.Day(), 0, 0, 0, 0, time.UTC)

	for key := range db.expDateToIssuer {
		v, err := time.Parse(kExpirationFormat, key)
		if err != nil {
			return []types.ExpDate{}, err
		}
		if !v.Before(truncatedNotBefore) {
			ed, err := types.NewExpDate(key)
			if err != nil {
				return dates, err
			}
			dates = append(dates, ed)
		}
	}
	return dates, nil
}

func (db *MockBackend) ListIssuersForExpirationDate(_ context.Context, expDate types.ExpDate) ([]types.Issuer,
	error) {
	return db.expDateToIssuer[expDate.ID()], nil
}

func (db *MockBackend) ListSerialsForExpirationDateAndIssuer(_ context.Context, expDate types.ExpDate,
	issuer types.Issuer) ([]types.Serial, error) {
	return db.expDateIssuerIDToSerials[expDate.ID()+issuer.ID()], nil
}

func (db *MockBackend) StreamSerialsForExpirationDateAndIssuer(ctx context.Context, expDate types.ExpDate,
	issuer types.Issuer, _ <-chan struct{}, sChan chan<- types.UniqueCertIdentifier) error {
	// Does not have to be performant! Not benchmarking the mock
	allSerials, err := db.ListSerialsForExpirationDateAndIssuer(ctx, expDate, issuer)
	if err != nil {
		return err
	}
	for _, s := range allSerials {
		sChan <- types.UniqueCertIdentifier{
			Issuer:    issuer,
			ExpDate:   expDate,
			SerialNum: s,
		}
	}
	return nil
}

func (ec *MockBackend) LoadAllLogStates(_ context.Context) ([]CertificateLog, error) {
	return nil, fmt.Errorf("Unimplemented")
}
