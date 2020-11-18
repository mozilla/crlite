package storage

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"sort"
	"testing"
	"time"
)

func mkExpDate(s string) ExpDate {
	expDate, err := NewExpDate(s)
	if err != nil {
		panic(err)
	}
	return expDate
}

func storeAndLoad(t *testing.T, serial Serial, expDate ExpDate, issuer Issuer, db StorageBackend, data []byte) {
	err := db.StoreCertificatePEM(context.TODO(), serial, expDate, issuer, data)
	if err != nil {
		t.Fatalf("Should have stored %d bytes: %+v", len(data), err)
	}

	t.Logf("Now loading %s/%s/%s", expDate.ID(), issuer.ID(), serial.ID())

	loaded, err := db.LoadCertificatePEM(context.TODO(), serial, expDate, issuer)
	if err != nil {
		t.Fatalf("Should have loaded: %+v", err)
	}

	if !bytes.Equal(data, loaded) {
		t.Fatalf("Data should match exactly - expected=[%+v] loaded=[%+v]", data, loaded)
	}
}

func BackendTestStoreLoad(t *testing.T, db StorageBackend) {
	expDate := mkExpDate("2050-05-20")
	issuer := NewIssuerFromString("test_file")

	storeAndLoad(t, NewSerialFromHex("01"), expDate, issuer, db, []byte{})
	storeAndLoad(t, NewSerialFromHex("02"), expDate, issuer, db, []byte{0x01})
	storeAndLoad(t, NewSerialFromHex("03"), expDate, issuer, db, []byte{0x00, 0x01, 0x02})
	storeAndLoad(t, NewSerialFromHex("04"), expDate, issuer, db, make([]byte, 1*1024*1024-128))

	// Load unknown
	_, err := db.LoadCertificatePEM(context.TODO(), NewSerialFromHex("FF"), expDate, issuer)
	if err == nil {
		t.Fatalf("Should not have loaded a missing file")
	}
}

func BackendTestListFiles(t *testing.T, db StorageBackend) {
	expectedFolders := []string{"2019-11-28"}
	issuerObj := NewIssuerFromString("aki")

	expDate := mkExpDate("2019-11-28")

	err := db.StoreCertificatePEM(context.TODO(), NewSerialFromHex("01"), expDate, issuerObj, []byte{0xDA, 0xDA})
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	// Normally the FilesystemDatabase object is responsible for this allocation
	err = db.AllocateExpDateAndIssuer(context.TODO(), expDate, issuerObj)
	if err != nil {
		t.Fatal(err)
	}

	refTime, err := time.Parse(time.RFC3339, "2016-11-29T15:04:05Z")
	if err != nil {
		t.Fatalf("Couldn't parse time %+v", err)
	}
	var expDates ExpDateList
	expDates, err = db.ListExpirationDates(context.TODO(), refTime)
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	sort.Sort(expDates)

	if len(expectedFolders) != len(expDates) {
		t.Errorf("Expected %s result %s", expectedFolders, expDates)
	}
	for i, val := range expectedFolders {
		if expDates[i].ID() != val {
			t.Errorf("Mismatch at idx=%d: expected %s got %s", i, val, expDates[i])
		}
	}

	issuers, err := db.ListIssuersForExpirationDate(context.TODO(), expDate)
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	expectedIssuers := []Issuer{
		NewIssuerFromString("aki"),
	}
	if !reflect.DeepEqual(expectedIssuers, issuers) {
		t.Fatalf("Failed ListIssuersForExpirationDate expected: %+v result: %+v", expectedIssuers, issuers)
	}
}

func BackendTestLogState(t *testing.T, db StorageBackend) {
	testLogURL := fmt.Sprintf("log.ct/%d", time.Now().Unix())

	log, err := db.LoadLogState(context.TODO(), "not a real log")
	if err != nil {
		t.Errorf("Unknown logs should be OK")
	}
	if log == nil {
		t.Fatalf("Log shouldn't be nil")
	}

	log, err = db.LoadLogState(context.TODO(), testLogURL)
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
	err = db.StoreLogState(context.TODO(), log)
	if err != nil {
		t.Errorf("Shouldn't have errored saving %v", err)
	}

	{
		updatedLog, err := db.LoadLogState(context.TODO(), testLogURL)
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
	err = db.StoreLogState(context.TODO(), log)
	if err != nil {
		t.Errorf("Shouldn't have errored saving %v", err)
	}

	{
		updatedLog, err := db.LoadLogState(context.TODO(), testLogURL)
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

func BackendTestListingCertificates(t *testing.T, db StorageBackend) {
	issuer := NewIssuerFromString("issuerAKI")
	expectedSerials := map[string][]Serial{
		"2019-11-28":    []Serial{NewSerialFromHex("01")},
		"2019-11-28-04": []Serial{NewSerialFromHex("02")},
		"2019-11-28-23": []Serial{NewSerialFromHex("03")},
	}

	for date, serials := range expectedSerials {
		for _, serial := range serials {
			err := db.StoreCertificatePEM(context.TODO(), serial, mkExpDate(date), issuer,
				[]byte{0xDA, 0xDA})
			if err != nil {
				t.Fatalf("%s", err.Error())
			}
		}
		// Normally the FilesystemDatabase object is responsible for this allocation
		err := db.AllocateExpDateAndIssuer(context.TODO(), mkExpDate(date), issuer)
		if err != nil {
			t.Fatal(err)
		}
	}

	list, err := db.ListExpirationDates(context.TODO(),
		time.Date(2010, time.January, 01, 12, 00, 00, 00, time.UTC))
	if err != nil {
		t.Error(err)
	}

	var count int
	for _, expDate := range list {
		resultList, err := db.ListSerialsForExpirationDateAndIssuer(context.TODO(), expDate, issuer)
		if err != nil {
			t.Error(err)
		}
		if !reflect.DeepEqual(expectedSerials[expDate.ID()], resultList) {
			t.Errorf("Expected equality %+v & %+v for date %s", expectedSerials[expDate.ID()], resultList, expDate.ID())
		}
		count += 1
	}

	if count != len(expectedSerials) {
		t.Errorf("Found %d entries, expected %d", count, len(expectedSerials))
	}
}
