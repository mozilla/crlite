package main

import (
	"reflect"
	"testing"

	"github.com/jcjones/ct-mapreduce/storage"
)

func Test_issuerDateTuple(t *testing.T) {
	ed, err := storage.NewExpDate("2050-12-31")
	if err != nil {
		t.Error(err)
	}
	tuple := issuerDateTuple{
		expDate: ed,
		issuer:  storage.NewIssuerFromString("an issuer"),
	}

	expected := "2050-12-31/an issuer"
	encoded := tuple.String()
	if encoded != expected {
		t.Errorf("Expected %s but got %s", expected, encoded)
	}

	newTuple := decodeIssuerDateTuple(encoded)
	if !reflect.DeepEqual(newTuple, tuple) {
		t.Errorf("Expected %+v but got %+v", tuple, newTuple)
	}
}
