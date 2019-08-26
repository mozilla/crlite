package storage

import (
	"bytes"
	"reflect"
	"sort"
	"testing"
	"time"
)

func storeAndLoad(t *testing.T, spki SPKI, expDate string, issuer string, db StorageBackend, data []byte) {
	err := db.StoreCertificatePEM(spki, expDate, issuer, data)
	if err != nil {
		t.Fatalf("Should have stored %d bytes: %+v", len(data), err)
	}

	t.Logf("Now loading %s/%s/%s", expDate, issuer, spki.ID())

	loaded, err := db.LoadCertificatePEM(spki, expDate, issuer)
	if err != nil {
		t.Fatalf("Should have loaded: %+v", err)
	}

	if !bytes.Equal(data, loaded) {
		t.Fatalf("Data should match exactly")
	}
}

func BackendTestStoreLoad(t *testing.T, db StorageBackend) {
	expDate := "1234"
	issuer := "test_file"

	storeAndLoad(t, SPKI{[]byte{0x01}}, expDate, issuer, db, []byte{})
	storeAndLoad(t, SPKI{[]byte{0x01}}, expDate, issuer, db, []byte{0x01})
	storeAndLoad(t, SPKI{[]byte{0x01}}, expDate, issuer, db, []byte{0x00, 0x01, 0x02})
	storeAndLoad(t, SPKI{[]byte{0x01}}, expDate, issuer, db, make([]byte, 1*1024*1024))

	// Load unknown
	_, err := db.LoadCertificatePEM(SPKI{[]byte{0x02}}, expDate, issuer)
	if err == nil {
		t.Fatalf("Should not have loaded a missing file")
	}
}

func BackendTestListFiles(t *testing.T, db StorageBackend) {
	expectedFolders := []string{"2017-11-28", "2018-11-28", "2019-11-28"}
	for _, expDate := range expectedFolders {
		md := NewIssuerMetadata(expDate, "aki", db)
		err := db.StoreIssuerMetadata(expDate, "aki", &md.Metadata)
		if err != nil {
			t.Fatalf("Failed to store: %v", err)
		}
	}

	err := db.StoreCertificatePEM(SPKI{[]byte{0x01}}, "2019-11-28", "aki", []byte{0xDA, 0xDA})
	if err != nil {
		t.Fatalf("%s", err.Error())
	}

	refTime, err := time.Parse(time.RFC3339, "2016-11-29T15:04:05Z")
	if err != nil {
		t.Fatalf("Couldn't parse time %+v", err)
	}
	expDates, err := db.ListExpirationDates(refTime)
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	sort.Strings(expDates)
	if !reflect.DeepEqual(expectedFolders, expDates) {
		t.Fatalf("Failed expected: %s result: %s", expectedFolders, expDates)
	}

	issuers, err := db.ListIssuersForExpirationDate("2019-11-28")
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	expectedIssuers := []string{"aki"}
	if !reflect.DeepEqual(expectedIssuers, issuers) {
		t.Fatalf("Failed expected: %s result: %s", expectedIssuers, issuers)
	}
}
