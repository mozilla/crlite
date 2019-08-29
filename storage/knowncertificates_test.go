package storage

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

func Test_KnownCertificatesStoreLoad(t *testing.T) {
	backend := NewMockBackend()
	testIssuer := NewIssuerFromString("test issuer")

	saver := NewKnownCertificates("date", testIssuer, backend)
	loader := NewKnownCertificates("date", testIssuer, backend)

	saver.known = []Serial{NewSerialFromHex("01"), NewSerialFromHex("03"), NewSerialFromHex("05")}

	if err := saver.Save(); err != nil {
		t.Error(err)
	}

	if len(loader.known) != 0 {
		t.Fatal("Loader should be empty")
	}

	if err := loader.Load(); err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(loader.known, saver.known) {
		t.Errorf("Loader and saver should be equal now: %s %s", saver.known, loader.known)
	}
}

func Test_MergeSmall(t *testing.T) {
	backend := NewMockBackend()
	testIssuer := NewIssuerFromString("test issuer")

	left := NewKnownCertificates("date", testIssuer, backend)
	right := NewKnownCertificates("date", testIssuer, backend)

	left.known = []Serial{NewSerialFromHex("01"), NewSerialFromHex("03"), NewSerialFromHex("05")}
	right.known = []Serial{NewSerialFromHex("04")}

	origText, err := json.Marshal(left.known)
	if err != nil {
		t.Error(err)
	}
	origTextR, err := json.Marshal(right.known)
	if err != nil {
		t.Error(err)
	}

	if string(origText) != `["AQ==","Aw==","BQ=="]` {
		t.Errorf("Invalid initial: left %s", string(origText))
	}
	if string(origTextR) != `["BA=="]` {
		t.Errorf("Invalid initial: right %s", string(origTextR))
	}

	err = left.Merge(right)
	if err != nil {
		t.Error(err)
	}

	mergedText, err := json.Marshal(left.known)
	if err != nil {
		t.Error(err)
	}
	if string(mergedText) != `["AQ==","Aw==","BA==","BQ=="]` {
		t.Error("Invalid initial: right")
	}
}

func Test_MergeOutOfOrder(t *testing.T) {
	backend := NewMockBackend()
	testIssuer := NewIssuerFromString("test issuer")

	left := NewKnownCertificates("date", testIssuer, backend)
	right := NewKnownCertificates("date", testIssuer, backend)

	left.known = []Serial{NewSerialFromHex("01"), NewSerialFromHex("02"), NewSerialFromHex("03"), NewSerialFromHex("00")}
	right.known = []Serial{NewSerialFromHex("04")}

	origText, err := json.Marshal(left.known)
	if err != nil {
		t.Error(err)
	}
	origTextR, err := json.Marshal(right.known)
	if err != nil {
		t.Error(err)
	}

	if string(origText) != `["AQ==","Ag==","Aw==","AA=="]` {
		t.Errorf("Invalid initial: left %s", origText)
	}
	if string(origTextR) != `["BA=="]` {
		t.Errorf("Invalid initial: right %s", origTextR)
	}

	err = left.Merge(right)
	if err.Error() != "Unsorted merge" {
		t.Errorf("Expected unsorted error!: %s", err)
	}
}

func Test_MergeDescending(t *testing.T) {
	backend := NewMockBackend()
	testIssuer := NewIssuerFromString("test issuer")

	left := NewKnownCertificates("date", testIssuer, backend)
	right := NewKnownCertificates("date", testIssuer, backend)

	left.known = []Serial{NewSerialFromHex("04"), NewSerialFromHex("03"), NewSerialFromHex("02"), NewSerialFromHex("01")}
	right.known = []Serial{NewSerialFromHex("00")}

	origText, err := json.Marshal(left.known)
	if err != nil {
		t.Error(err)
	}
	origTextR, err := json.Marshal(right.known)
	if err != nil {
		t.Error(err)
	}

	if string(origText) != `["BA==","Aw==","Ag==","AQ=="]` {
		t.Errorf("Invalid initial: left %s", origText)
	}
	if string(origTextR) != `["AA=="]` {
		t.Errorf("Invalid initial: right %s", origTextR)
	}

	err = left.Merge(right)
	if err.Error() != "Unsorted merge" {
		t.Errorf("Expected unsorted error!: %s", err)
	}
}

func Test_MergeDuplicatesEnd(t *testing.T) {
	backend := NewMockBackend()
	testIssuer := NewIssuerFromString("test issuer")

	left := NewKnownCertificates("date", testIssuer, backend)
	right := NewKnownCertificates("date", testIssuer, backend)

	left.known = []Serial{NewSerialFromHex("01"), NewSerialFromHex("02"), NewSerialFromHex("03"), NewSerialFromHex("04")}
	right.known = []Serial{NewSerialFromHex("04")}

	origText, err := json.Marshal(left.known)
	if err != nil {
		t.Error(err)
	}
	origTextR, err := json.Marshal(right.known)
	if err != nil {
		t.Error(err)
	}

	if string(origText) != `["AQ==","Ag==","Aw==","BA=="]` {
		t.Error("Invalid initial: left")
	}
	if string(origTextR) != `["BA=="]` {
		t.Error("Invalid initial: right")
	}

	err = left.Merge(right)
	if err != nil {
		t.Error(err)
	}
	mergedText, err := json.Marshal(left.known)
	if err != nil {
		t.Error(err)
	}

	if string(mergedText) != `["AQ==","Ag==","Aw==","BA=="]` {
		t.Errorf("Invalid merge: %s", string(mergedText))
	}
}

func Test_MergeDuplicatesMiddle(t *testing.T) {
	backend := NewMockBackend()
	testIssuer := NewIssuerFromString("test issuer")

	left := NewKnownCertificates("date", testIssuer, backend)
	right := NewKnownCertificates("date", testIssuer, backend)

	left.known = []Serial{NewSerialFromHex("01"), NewSerialFromHex("02"), NewSerialFromHex("04"), NewSerialFromHex("05")}
	right.known = []Serial{NewSerialFromHex("02"), NewSerialFromHex("03"), NewSerialFromHex("04")}

	origText, err := json.Marshal(left.known)
	if err != nil {
		t.Error(err)
	}
	origTextR, err := json.Marshal(right.known)
	if err != nil {
		t.Error(err)
	}

	if string(origText) != `["AQ==","Ag==","BA==","BQ=="]` {
		t.Error("Invalid initial: left")
	}
	if string(origTextR) != `["Ag==","Aw==","BA=="]` {
		t.Error("Invalid initial: right")
	}

	err = left.Merge(right)
	if err != nil {
		t.Error(err)
	}
	mergedText, err := json.Marshal(left.known)
	if err != nil {
		t.Error(err)
	}

	if string(mergedText) != `["AQ==","Ag==","Aw==","BA==","BQ=="]` {
		t.Errorf("Invalid merge: %s", string(mergedText))
	}
}

func Test_Unknown(t *testing.T) {
	backend := NewMockBackend()
	testIssuer := NewIssuerFromString("test issuer")

	kc := NewKnownCertificates("date", testIssuer, backend)

	kc.known = []Serial{NewSerialFromHex("01"), NewSerialFromHex("02"), NewSerialFromHex("03"), NewSerialFromHex("04")}

	origText, err := json.Marshal(kc.known)
	if err != nil {
		t.Error(err)
	}

	if string(origText) != `["AQ==","Ag==","Aw==","BA=="]` {
		t.Error("Invalid initial")
	}

	for _, bi := range kc.known {
		if u, _ := kc.WasUnknown(bi); u == true {
			t.Errorf("%v should have been known", bi)
		}
	}

	if u, _ := kc.WasUnknown(NewSerialFromHex("05")); u == false {
		t.Error("5 should not have been known")
	}

	if u, _ := kc.WasUnknown(NewSerialFromHex("05")); u == true {
		t.Error("5 should now have been known")
	}

	endText, err := json.Marshal(kc.known)
	if err != nil {
		t.Error(err)
	}

	if string(endText) != `["AQ==","Ag==","Aw==","BA==","BQ=="]` {
		t.Errorf("Invalid end %s", endText)
	}
}

func Test_IsSorted(t *testing.T) {
	backend := NewMockBackend()
	testIssuer := NewIssuerFromString("test issuer")

	kc := NewKnownCertificates("date", testIssuer, backend)
	kc.known = []Serial{NewSerialFromHex("01"), NewSerialFromHex("02"), NewSerialFromHex("03"), NewSerialFromHex("04")}

	if kc.IsSorted() != true {
		t.Error("Should be sorted")
	}

	kc.known = []Serial{NewSerialFromHex("01"), NewSerialFromHex("03"), NewSerialFromHex("02"), NewSerialFromHex("04")}

	if kc.IsSorted() != false {
		t.Error("Should not be sorted")
	}
}

func BenchmarkMerge(b *testing.B) {
	backend := NewMockBackend()
	testIssuer := NewIssuerFromString("test issuer")

	b.StopTimer()

	left := NewKnownCertificates("date", testIssuer, backend)
	right := NewKnownCertificates("date", testIssuer, backend)

	var i int64
	for i = 0; i < 128*1024*1024; i++ {
		serial := NewSerialFromHex(fmt.Sprintf("%X", i))
		if i%2 == 0 {
			left.known = append(left.known, serial)
		} else {
			right.known = append(right.known, serial)
		}
	}

	b.StartTimer()

	err := left.Merge(right)
	if err != nil {
		b.Error(err)
	}
}

func Test_KnownCertificatesKnown(t *testing.T) {
	backend := NewMockBackend()
	testIssuer := NewIssuerFromString("test issuer")

	kc := NewKnownCertificates("date", testIssuer, backend)

	kc.known = []Serial{NewSerialFromHex("01"), NewSerialFromHex("03"), NewSerialFromHex("05")}

	result := kc.Known()
	if !reflect.DeepEqual(kc.known, result) {
		t.Error("Should be an accessor")
	}
}
