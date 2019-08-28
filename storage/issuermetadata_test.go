package storage

import (
	"testing"
)

func Test_DuplicateCRLs(t *testing.T) {
	meta := NewIssuerMetadata("date", Issuer{}, NewMockBackend())

	meta.addCRL("ldaps://ldap.crl")
	meta.addCRL("schema://192.168.1.1:129/file.crl")
	meta.addCRL("http://::1/file.crl")

	if len(meta.Metadata.Crls) != 1 {
		t.Error("Only one of these CRLs was valid")
	}

	meta.addCRL("http://::1/file.crl")
	if len(meta.Metadata.Crls) != 1 {
		t.Error("Shouldn't dupe")
	}

	meta.addCRL("http://::1/file.crl ")
	if len(meta.Metadata.Crls) != 1 {
		t.Error("Shouldn't dupe even with a space")
	}

	meta.addCRL(" http://::1/file.crl ")
	if len(meta.Metadata.Crls) != 1 {
		t.Error("Shouldn't dupe even with spaces")
	}

	meta.addCRL(" http://::1/file.crl   ")
	if len(meta.Metadata.Crls) != 1 {
		t.Error("Shouldn't dupe even with spaces")
	}

}
