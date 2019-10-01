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
	backend.Data[kc.id()] = testList

	origText, err := json.Marshal(testList)
	if err != nil {
		t.Error(err)
	}

	if string(origText) != `["AQ==","Ag==","Aw==","BA=="]` {
		t.Errorf("Invalid initial: %v", string(origText))
	}

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

	endText, err := json.Marshal(backend.Data[kc.id()])
	if err != nil {
		t.Error(err)
	}

	if string(endText) != `["AQ==","Ag==","Aw==","BA==","BQ=="]` {
		t.Errorf("Invalid end %s", endText)
	}
}

func Test_KnownCertificatesKnown(t *testing.T) {
	backend := NewMockRemoteCache()
	testIssuer := NewIssuerFromString("test issuer")

	kc := NewKnownCertificates("date", testIssuer, backend)

	backend.Data[kc.id()] = []Serial{NewSerialFromHex("01"), NewSerialFromHex("03"), NewSerialFromHex("05")}

	result := kc.Known()
	if !reflect.DeepEqual(backend.Data[kc.id()], result) {
		t.Error("Should be an accessor")
	}
}
