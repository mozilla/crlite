package main

import (
	"reflect"
	"testing"

	"github.com/jcjones/ct-mapreduce/storage"
)

func Test_issuerDateTuple(t *testing.T) {
	tuple := issuerDateTuple{
		expDate: "20501231",
		issuer:  storage.NewIssuerFromString("an issuer"),
	}

	expected := "20501231/an issuer"
	encoded := tuple.String()
	if encoded != expected {
		t.Errorf("Expected %s but got %s", expected, encoded)
	}

	newTuple := decodeIssuerDateTuple(encoded)
	if !reflect.DeepEqual(newTuple, tuple) {
		t.Errorf("Expected %+v but got %+v", tuple, newTuple)
	}
}
