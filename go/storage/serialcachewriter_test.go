package storage

import (
	"encoding/json"
	"github.com/mozilla/crlite/go"
	"testing"
	"time"
)

func Test_SerialCacheWriter(t *testing.T) {
	backend := NewMockRemoteCache()
	testIssuer := types.NewIssuerFromString("test issuer")

	expDate, err := types.NewExpDate("2029-01-30")
	if err != nil {
		t.Error(err)
	}
	kc := NewSerialCacheWriter(expDate, testIssuer, backend)

	testList := []types.Serial{
		types.NewSerialFromHex("01"),
		types.NewSerialFromHex("02"),
		types.NewSerialFromHex("03"),
		types.NewSerialFromHex("04"),
	}
	testStrings := make([]string, len(testList))
	for i, serial := range testList {
		testStrings[i] = serial.BinaryString()
	}
	backend.Data[kc.serialId()] = testStrings

	for _, bi := range testList {
		if u, _ := kc.Insert(bi); u == true {
			t.Errorf("%v should have been known, but was apparently unknown", bi)
		}
	}

	if u, _ := kc.Insert(types.NewSerialFromHex("05")); u == false {
		t.Error("5 should not have been known")
	}

	if u, _ := kc.Insert(types.NewSerialFromHex("05")); u == true {
		t.Error("5 should now have been known")
	}

	endText, err := json.Marshal(backend.Data[kc.serialId()])
	if err != nil {
		t.Error(err)
	}

	if string(endText) != `["\u0001","\u0002","\u0003","\u0004","\u0005"]` {
		t.Errorf("Invalid end %s", endText)
	}
}

func Test_SerialCacheReader(t *testing.T) {
	backend := NewMockRemoteCache()
	testIssuer := types.NewIssuerFromString("test issuer")

	expDate, err := types.NewExpDate("2029-01-30")
	if err != nil {
		t.Error(err)
	}
	kc := NewSerialCacheReader(expDate, testIssuer, backend)

	testList := []types.Serial{types.NewSerialFromHex("01"), types.NewSerialFromHex("03"), types.NewSerialFromHex("05")}
	testStrings := make([]string, len(testList))
	for i, serial := range testList {
		testStrings[i] = serial.BinaryString()
	}
	backend.Data[kc.serialId()] = testStrings

	result := kc.Known()
	if kc.Count() != 3 {
		t.Errorf("Expected 3, got %d", kc.Count())
	}
	count := 0
	for _, input := range testList {
		for _, output := range result {
			if input.BinaryString() == output.BinaryString() {
				count += 1
				break
			}
		}
	}
	if count != 3 {
		t.Errorf("Expected 3, got %d", kc.Count())
	}
}

func Test_ExpireAt(t *testing.T) {
	backend := NewMockRemoteCache()
	testIssuer := types.NewIssuerFromString("test issuer")

	date := time.Date(2004, 01, 20, 4, 22, 19, 44, time.UTC)
	expDate := types.NewExpDateFromTime(date)

	kc := NewSerialCacheWriter(expDate, testIssuer, backend)

	if u, _ := kc.Insert(types.NewSerialFromHex("05")); u == false {
		t.Error("5 should not have been known")
	}

	if len(backend.Expirations) != 1 {
		t.Error("Should have been length 1")
	}

	val, ok := backend.Expirations["serials::2004-01-20-04::test issuer"]
	if !ok {
		t.Errorf("Expected exp date of 2004-01-20-04 but got %+v", backend.Expirations)
	}
	expected := time.Date(2004, 01, 20, 4, 0, 0, 0, time.UTC)
	if val != expected {
		t.Errorf("Expected the expiration date to match: %v != %v", val, expected)
	}
}
