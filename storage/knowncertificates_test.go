package storage

import (
	"encoding/json"
	"reflect"
	"testing"
)

func Test_Unknown(t *testing.T) {
	backend := NewMockRemoteCache()
	testIssuer := NewIssuerFromString("test issuer")

	kc := NewKnownCertificates("date", testIssuer, backend)

	testList := []Serial{NewSerialFromHex("01"), NewSerialFromHex("02"), NewSerialFromHex("03"), NewSerialFromHex("04")}
	testStrings := make([]string, len(testList))
	for i, serial := range testList {
		testStrings[i] = serial.String()
	}
	backend.Data["serials::"+kc.id()] = testStrings

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

	endText, err := json.Marshal(backend.Data["serials::"+kc.id()])
	if err != nil {
		t.Error(err)
	}

	if string(endText) != `["01","02","03","04","05"]` {
		t.Errorf("Invalid end %s", endText)
	}
}

func Test_KnownCertificatesKnown(t *testing.T) {
	backend := NewMockRemoteCache()
	testIssuer := NewIssuerFromString("test issuer")

	kc := NewKnownCertificates("date", testIssuer, backend)

	testList := []Serial{NewSerialFromHex("01"), NewSerialFromHex("03"), NewSerialFromHex("05")}
	testStrings := make([]string, len(testList))
	for i, serial := range testList {
		testStrings[i] = serial.String()
	}
	backend.Data["serials::"+kc.id()] = testStrings

	result := kc.Known()
	if !reflect.DeepEqual(testList, result) {
		t.Errorf("Known should get the data")
	}
}
