package storage

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"testing"
	"time"

	newx509 "github.com/google/certificate-transparency-go/x509"
)

func Test_DuplicateCRLs(t *testing.T) {
	meta := NewIssuerMetadata("2525-06-06", NewIssuerFromString("issuer"), NewMockRemoteCache())

	if err := meta.addCRL("ldaps://ldap.crl"); err != nil {
		t.Error(err)
	}
	if err := meta.addCRL("schema://192.168.1.1:129/file.crl"); err != nil {
		t.Error(err)
	}
	if err := meta.addCRL("http://::1/file.crl"); err != nil {
		t.Error(err)
	}

	if len(meta.CRLs()) != 1 {
		t.Error("Only one of these CRLs was valid")
	}

	if err := meta.addCRL("http://::1/file.crl"); err != nil {
		t.Error(err)
	}
	if len(meta.CRLs()) != 1 {
		t.Error("Shouldn't dupe")
	}

	if err := meta.addCRL("http://::1/file.crl "); err != nil {
		t.Error(err)
	}
	if len(meta.CRLs()) != 1 {
		t.Error("Shouldn't dupe even with a space")
	}

	if err := meta.addCRL(" http://::1/file.crl "); err != nil {
		t.Error(err)
	}
	if len(meta.CRLs()) != 1 {
		t.Error("Shouldn't dupe even with spaces")
	}

	if err := meta.addCRL(" http://::1/file.crl   "); err != nil {
		t.Error(err)
	}
	if len(meta.CRLs()) != 1 {
		t.Error("Shouldn't dupe even with spaces")
	}
}

func makeCert(t *testing.T, issuerDN string, expDate string, serial Serial) *newx509.Certificate {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Error(err)
		return nil
	}

	notAfter, err := time.Parse("2006-01-02", expDate)
	if err != nil {
		t.Fatalf("Programmer error on timestamp %s: %v", expDate, err)
	}
	notBefore := notAfter.AddDate(-1, 0, 0)

	template := x509.Certificate{
		SerialNumber: serial.AsBigInt(),
		Subject: pkix.Name{
			CommonName: issuerDN,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		IsCA:      true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template,
		privKey.Public(), privKey)
	if err != nil {
		t.Error(err)
		return nil
	}

	obj, err := newx509.ParseCertificate(certBytes)
	if err != nil {
		t.Error(err)
		return nil
	}

	return obj
}

func Test_Accumulate(t *testing.T) {
	issuerCN := "My First Issuer (tm)"
	issuerDN := fmt.Sprintf("CN=%s", issuerCN)
	firstCert := makeCert(t, issuerCN, "2001-01-01", NewSerialFromHex("00"))

	issuerObj := NewIssuer(firstCert)
	meta := NewIssuerMetadata("3535-09-01", issuerObj, NewMockRemoteCache())

	seenBefore, err := meta.Accumulate(firstCert)
	if err != nil {
		t.Error(err)
	}
	if seenBefore != false {
		t.Error("Should have been a new day")
	}

	nextCert := makeCert(t, issuerCN, "2001-01-01", NewSerialFromHex("01"))
	seenBefore, err = meta.Accumulate(nextCert)
	if err != nil {
		t.Error(err)
	}
	if seenBefore != true {
		t.Error("Should have not have been a new day")
	}

	if len(meta.CRLs()) != 0 {
		t.Error("There should have been no CRL dps")
	}

	if len(meta.Issuers()) != 1 {
		t.Errorf("There should have been a single issuer DN: %+v", meta.Issuers())
	}

	if meta.Issuers()[0] != issuerDN {
		t.Errorf("Expected %s but got %s", issuerDN, meta.Issuers()[0])
	}
}
