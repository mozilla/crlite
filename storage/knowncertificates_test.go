package storage

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

func Test_Unknown(t *testing.T) {
	backend := NewMockRemoteCache()
	testIssuer := NewIssuerFromString("test issuer")

	kc := NewKnownCertificates("2029-01-30", testIssuer, backend)

	testList := []Serial{
		NewSerialFromHex("01"),
		NewSerialFromHex("02"),
		NewSerialFromHex("03"),
		NewSerialFromHex("04"),
	}
	testStrings := make([]string, len(testList))
	for i, serial := range testList {
		testStrings[i] = serial.BinaryString()
	}
	backend.Data[kc.serialId()] = testStrings

	for _, bi := range testList {
		if u, _ := kc.WasUnknown(bi); u == true {
			t.Errorf("%v should have been known, but was apparently unknown", bi)
		}
	}

	if u, _ := kc.WasUnknown(NewSerialFromHex("05")); u == false {
		t.Error("5 should not have been known")
	}

	if u, _ := kc.WasUnknown(NewSerialFromHex("05")); u == true {
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

func Test_KnownCertificatesKnown(t *testing.T) {
	backend := NewMockRemoteCache()
	testIssuer := NewIssuerFromString("test issuer")

	kc := NewKnownCertificates("2029-01-30", testIssuer, backend)

	testList := []Serial{NewSerialFromHex("01"), NewSerialFromHex("03"), NewSerialFromHex("05")}
	testStrings := make([]string, len(testList))
	for i, serial := range testList {
		testStrings[i] = serial.BinaryString()
	}
	backend.Data[kc.serialId()] = testStrings

	result := kc.Known()
	if !reflect.DeepEqual(testList, result) {
		t.Errorf("Known should get the data: %+v // %+v", testList, result)
	}
}

func Test_KnownCertificatesKnownMultipleLists(t *testing.T) {
	backend := NewMockRemoteCache()
	testIssuer := NewIssuerFromString("test issuer")

	kc := NewKnownCertificates("2029-02-30", testIssuer, backend)

	testList := []Serial{NewSerialFromHex("01"), NewSerialFromHex("03"), NewSerialFromHex("05")}

	for i, serial := range testList {
		id := kc.serialId(fmt.Sprintf("-%02d", i))
		if id != fmt.Sprintf("serials::2029-02-30-%02d::test issuer", i) {
			t.Errorf("id=%s didn't match for %d", id, i)
		}
		backend.Data[id] = []string{serial.BinaryString()}
	}

	result := kc.Known()
	if !reflect.DeepEqual(testList, result) {
		t.Errorf("Known should get the data: %+v // %+v", testList, result)
	}
}
