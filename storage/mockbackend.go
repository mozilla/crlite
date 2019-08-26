package storage

import (
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"time"
)

type MockBackend struct {
	expDateToIssuer map[string][]string
	store           map[string][]byte
}

func NewMockBackend() *MockBackend {
	return &MockBackend{make(map[string][]string), make(map[string][]byte)}
}

func (db *MockBackend) MarkDirty(id string) error {
	return nil
}

func (db *MockBackend) noteExpDateIssuer(expDate string, issuer string) {
	issuers, ok := db.expDateToIssuer[expDate]
	if !ok {
		issuers = []string{}
	}
	i := sort.SearchStrings(issuers, issuer)
	if i < len(issuers) && issuers[i] == issuer {
		// already noted
	} else {
		issuers = append(issuers, issuer)
		sort.Strings(issuers)
		db.expDateToIssuer[expDate] = issuers
	}
}

func (db *MockBackend) StoreCertificatePEM(spki SPKI, expDate string, issuer string, b []byte) error {
	db.noteExpDateIssuer(expDate, issuer)
	db.store["pem"+expDate+issuer] = b
	return nil
}

func (db *MockBackend) StoreLogState(logURL string, log *CertificateLog) error {
	data, err := json.Marshal(log)
	if err != nil {
		return err
	}
	db.store["logstate"+logURL] = data
	return nil
}

func (db *MockBackend) StoreIssuerMetadata(expDate string, issuer string, metadata *Metadata) error {
	db.noteExpDateIssuer(expDate, issuer)
	data, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	db.store["metadata"+expDate+issuer] = data
	return nil
}

func (db *MockBackend) StoreIssuerKnownSerials(expDate string, issuer string, serials []*big.Int) error {
	db.noteExpDateIssuer(expDate, issuer)
	data, err := json.Marshal(serials)
	if err != nil {
		return err
	}
	db.store["serials"+expDate+issuer] = data
	return nil
}

func (db *MockBackend) LoadCertificatePEM(spki SPKI, expDate string, issuer string) ([]byte, error) {
	data, ok := db.store["pem"+expDate+issuer]
	if ok {
		return data, nil
	}
	return []byte{}, fmt.Errorf("Couldn't find")
}

func (db *MockBackend) LoadLogState(logURL string) (*CertificateLog, error) {
	data, ok := db.store["logstate"+logURL]
	if ok {
		var log *CertificateLog
		err := json.Unmarshal(data, &log)
		return log, err
	}
	return nil, fmt.Errorf("Couldn't find")
}

func (db *MockBackend) LoadIssuerMetadata(expDate string, issuer string) (*Metadata, error) {
	data, ok := db.store["metadata"+expDate+issuer]
	if ok {
		var meta *Metadata
		err := json.Unmarshal(data, &meta)
		return meta, err
	}
	return nil, fmt.Errorf("Couldn't find")
}

func (db *MockBackend) LoadIssuerKnownSerials(expDate string, issuer string) ([]*big.Int, error) {
	data, ok := db.store["serials"+expDate+issuer]
	if ok {
		var serials []*big.Int
		err := json.Unmarshal(data, &serials)
		return serials, err
	}
	return nil, fmt.Errorf("Couldn't find")
}

func (db *MockBackend) ListExpirationDates(aNotBefore time.Time) ([]string, error) {
	dates := []string{}
	truncatedNotBefore := time.Date(aNotBefore.Year(), aNotBefore.Month(), aNotBefore.Day(), 0, 0, 0, 0, time.UTC)

	for key := range db.expDateToIssuer {
		v, err := time.Parse(kExpirationFormat, key)
		if err != nil {
			return []string{}, err
		}
		if !v.Before(truncatedNotBefore) {
			dates = append(dates, key)
		}
	}
	return dates, nil
}

func (db *MockBackend) ListIssuersForExpirationDate(expDate string) ([]string, error) {
	return db.expDateToIssuer[expDate], nil
}
