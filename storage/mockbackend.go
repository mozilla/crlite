package storage

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

type MockBackend struct {
	expDateToIssuer map[string][]Issuer
	store           map[string][]byte
}

func NewMockBackend() *MockBackend {
	return &MockBackend{
		expDateToIssuer: make(map[string][]Issuer),
		store:           make(map[string][]byte),
	}
}

func (db *MockBackend) MarkDirty(id string) error {
	return nil
}

func (db *MockBackend) AllocateExpDateAndIssuer(expDate string, issuer Issuer) error {
	issuers, ok := db.expDateToIssuer[expDate]
	if !ok {
		issuers = []Issuer{}
	}
	i := sort.Search(len(issuers), func(i int) bool { return strings.Compare(issuers[i].ID(), issuer.ID()) >= 0 })
	if i < len(issuers) && issuers[i].ID() == issuer.ID() {
		// already noted
	} else {
		issuers = append(issuers, Issuer{})
		copy(issuers[i+1:], issuers[i:])
		issuers[i] = issuer
		db.expDateToIssuer[expDate] = issuers
	}
	return nil
}

func (db *MockBackend) StoreCertificatePEM(serial Serial, expDate string, issuer Issuer, b []byte) error {
	db.store["pem"+expDate+issuer.ID()+serial.ID()] = b
	return nil
}

func (db *MockBackend) StoreLogState(log *CertificateLog) error {
	data, err := json.Marshal(log)
	if err != nil {
		return err
	}
	db.store["logstate"+log.ShortURL] = data
	return nil
}

func (db *MockBackend) LoadCertificatePEM(serial Serial, expDate string, issuer Issuer) ([]byte, error) {
	data, ok := db.store["pem"+expDate+issuer.ID()+serial.ID()]
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
	return &CertificateLog{
		ShortURL: logURL,
	}, nil
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

func (db *MockBackend) ListIssuersForExpirationDate(expDate string) ([]Issuer, error) {
	return db.expDateToIssuer[expDate], nil
}
