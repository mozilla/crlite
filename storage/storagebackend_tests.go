package storage

import (
	"bytes"
	"fmt"
	"reflect"
	"sort"
	"testing"
	"time"
)

func storeAndLoad(t *testing.T, serial Serial, expDate string, issuer Issuer, db StorageBackend, data []byte) {
	err := db.StoreCertificatePEM(serial, expDate, issuer, data)
	if err != nil {
		t.Fatalf("Should have stored %d bytes: %+v", len(data), err)
	}

	t.Logf("Now loading %s/%s/%s", expDate, issuer.ID(), serial.ID())

	loaded, err := db.LoadCertificatePEM(serial, expDate, issuer)
	if err != nil {
		t.Fatalf("Should have loaded: %+v", err)
	}

	if !bytes.Equal(data, loaded) {
		t.Fatalf("Data should match exactly - expected=[%+v] loaded=[%+v]", data, loaded)
	}
}

func BackendTestStoreLoad(t *testing.T, db StorageBackend) {
	expDate := "1234"
	issuer := NewIssuerFromString("test_file")

	storeAndLoad(t, NewSerialFromHex("01"), expDate, issuer, db, []byte{})
	storeAndLoad(t, NewSerialFromHex("02"), expDate, issuer, db, []byte{0x01})
	storeAndLoad(t, NewSerialFromHex("03"), expDate, issuer, db, []byte{0x00, 0x01, 0x02})
	storeAndLoad(t, NewSerialFromHex("04"), expDate, issuer, db, make([]byte, 1*1024*1024))

	// Load unknown
	_, err := db.LoadCertificatePEM(NewSerialFromHex("FF"), expDate, issuer)
	if err == nil {
		t.Fatalf("Should not have loaded a missing file")
	}
}

func BackendTestListFiles(t *testing.T, db StorageBackend) {
	expectedFolders := []string{"2017-11-28", "2018-11-28", "2019-11-28"}
	issuerObj := NewIssuerFromString("aki")

	for _, expDate := range expectedFolders {
		md := NewIssuerMetadata(expDate, issuerObj, db)
		err := db.StoreIssuerMetadata(expDate, issuerObj, &md.Metadata)
		if err != nil {
			t.Fatalf("Failed to store: %v", err)
		}
	}

	err := db.StoreCertificatePEM(NewSerialFromHex("01"), "2019-11-28", issuerObj, []byte{0xDA, 0xDA})
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
	expectedIssuers := []Issuer{
		NewIssuerFromString("aki"),
	}
	if !reflect.DeepEqual(expectedIssuers, issuers) {
		t.Fatalf("Failed expected: %+v result: %+v", expectedIssuers, issuers)
	}
}

func BackendTestLogState(t *testing.T, db StorageBackend) {
	testLogURL := fmt.Sprintf("log.ct/%d", time.Now().Unix())

	log, err := db.LoadLogState("not a real log")
	if err != nil {
		t.Errorf("Unknown logs should be OK")
	}
	if log == nil {
		t.Fatalf("Log shouldn't be nil")
	}

	log, err = db.LoadLogState(testLogURL)
	if err != nil {
		t.Errorf("Should not error %v", err)
	}
	if log.ShortURL != testLogURL {
		t.Errorf("Unexpected URL %s", log.ShortURL)
	}
	if log.MaxEntry != 0 || !log.LastEntryTime.IsZero() {
		t.Errorf("Expected a blank log  %s", log.String())
	}

	log.MaxEntry = 9
	err = db.StoreLogState(log)
	if err != nil {
		t.Errorf("Shouldn't have errored saving %v", err)
	}

	{
		updatedLog, err := db.LoadLogState(testLogURL)
		if err != nil {
			t.Errorf("Unexpected error %s: %v", updatedLog.String(), err)
		}
		if updatedLog.ShortURL != testLogURL {
			t.Errorf("Unexpected URL %s", updatedLog.ShortURL)
		}
		if updatedLog.MaxEntry != 9 || !updatedLog.LastEntryTime.IsZero() {
			t.Errorf("Expected the MaxEntry to be 9 and the time to be unset %s", updatedLog.String())
		}
	}

	log.MaxEntry = 0xDEADBEEF
	log.LastEntryTime = time.Unix(1567016306, 0)
	err = db.StoreLogState(log)
	if err != nil {
		t.Errorf("Shouldn't have errored saving %v", err)
	}

	{
		updatedLog, err := db.LoadLogState(testLogURL)
		if err != nil {
			t.Errorf("Unexpected error %s: %v", updatedLog.String(), err)
		}
		if updatedLog.ShortURL != testLogURL {
			t.Errorf("Unexpected URL %s", updatedLog.ShortURL)
		}
		if updatedLog.MaxEntry != 0xDEADBEEF {
			t.Errorf("Expected the MaxEntry to be 0xDEADBEEF %s", updatedLog.String())
		}
		if updatedLog.LastEntryTime.IsZero() {
			t.Errorf("Expected the MaxEntry to be non-zero %s", updatedLog.String())
		}
		if updatedLog.LastEntryTime.Unix() != 1567016306 {
			t.Errorf("Expected the LastEntryTime to be 1567016306. %s", updatedLog.String())
		}
	}
}

func BackendTestKnownCertificates(t *testing.T, db StorageBackend) {
	testIssuer := NewIssuerFromString("test issuer")

	{
		k := NewKnownCertificates("date", testIssuer, db)
		err := k.Load()
		if err == nil {
			t.Errorf("Should have failed to load an unknown Known Certificates file")
		}

		k.known = []Serial{NewSerialFromHex("01"), NewSerialFromHex("03"), NewSerialFromHex("05")}
		err = k.Save()
		if err != nil {
			t.Errorf("Should have saved safely %v", err)
		}
	}

	loaded := NewKnownCertificates("date", testIssuer, db)
	if len(loaded.Known()) != 0 {
		t.Errorf("Should have started empty")
	}
	err := loaded.Load()
	if err != nil {
		t.Errorf("Should have loaded safely %v", err)
	}

	if len(loaded.Known()) != 3 {
		t.Errorf("Should have had 3 entries: %v", loaded.Known())
	}
}

func BackendTestIssuerMetadata(t *testing.T, db StorageBackend) {
	{
		meta := NewIssuerMetadata("date", NewIssuerFromString("issuer"), db)
		err := meta.Load()
		if err == nil {
			t.Errorf("Should have failed to load an unknown Issuer Metadata file")
		}

		meta.addCRL("http://::1/file.crl")
		err = meta.Save()
		if err != nil {
			t.Errorf("Should have saved safely %v", err)
		}
	}

	m := NewIssuerMetadata("date", NewIssuerFromString("issuer"), db)
	if len(m.Metadata.Crls) != 0 {
		t.Errorf("Should have started empty")
	}
	err := m.Load()
	if err != nil {
		t.Errorf("Should have loaded safely %v", err)
	}

	if len(m.Metadata.Crls) != 1 {
		t.Errorf("Should have loaded one CRL")
	}
}
