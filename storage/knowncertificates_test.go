package storage

import (
	"encoding/json"
	"math/big"
	"testing"
)

func Test_MergeSmall(t *testing.T) {
	left := NewKnownCertificates("", 0644)
	right := NewKnownCertificates("", 0644)

	left.known = []*big.Int{big.NewInt(1), big.NewInt(3), big.NewInt(5)}
	right.known = []*big.Int{big.NewInt(4)}

	origText, err := json.Marshal(left.known)
	if err != nil {
		t.Error(err)
	}
	origTextR, err := json.Marshal(right.known)
	if err != nil {
		t.Error(err)
	}

	if string(origText) != "[1,3,5]" {
		t.Error("Invalid initial: left")
	}
	if string(origTextR) != "[4]" {
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
	if string(mergedText) != "[1,3,4,5]" {
		t.Error("Invalid initial: right")
	}
}

func Test_MergeOutOfOrder(t *testing.T) {
	left := NewKnownCertificates("", 0644)
	right := NewKnownCertificates("", 0644)

	left.known = []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(0)}
	right.known = []*big.Int{big.NewInt(4)}

	origText, err := json.Marshal(left.known)
	if err != nil {
		t.Error(err)
	}
	origTextR, err := json.Marshal(right.known)
	if err != nil {
		t.Error(err)
	}

	if string(origText) != "[1,2,3,0]" {
		t.Error("Invalid initial: left")
	}
	if string(origTextR) != "[4]" {
		t.Error("Invalid initial: right")
	}

	err = left.Merge(right)
	if err.Error() != "Unsorted 3 (3, 0)" {
		t.Errorf("Expected unsorted error!: %s", err)
	}
}

func Test_MergeDescending(t *testing.T) {
	left := NewKnownCertificates("", 0644)
	right := NewKnownCertificates("", 0644)

	left.known = []*big.Int{big.NewInt(4), big.NewInt(3), big.NewInt(2), big.NewInt(1)}
	right.known = []*big.Int{big.NewInt(0)}

	origText, err := json.Marshal(left.known)
	if err != nil {
		t.Error(err)
	}
	origTextR, err := json.Marshal(right.known)
	if err != nil {
		t.Error(err)
	}

	if string(origText) != "[4,3,2,1]" {
		t.Error("Invalid initial: left")
	}
	if string(origTextR) != "[0]" {
		t.Error("Invalid initial: right")
	}

	err = left.Merge(right)
	if err.Error() != "Unsorted 2 (4, 3)" {
		t.Errorf("Expected unsorted error!: %s", err)
	}
}
