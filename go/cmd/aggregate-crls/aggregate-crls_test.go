package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io/ioutil"
	"math/big"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"
)

func Test_makeFilenameFromUrl(t *testing.T) {
	names := make(map[string]bool)

	checkCollision := func(t *testing.T, list []string, db map[string]bool) {
		for _, crl := range list {
			url, _ := url.Parse(crl)

			filename := makeFilenameFromUrl(*url)
			if db[filename] {
				t.Errorf("Name collision: %s in %v", filename, db)
			}

			db[filename] = true
		}
	}

	crls := []string{"http://repository.net/crl/1000-1/complete.crl",
		"http://repository.net/crl/100-1/complete.crl",
		"http://repository.net/crl/10-1/complete.crl",
		"http://repository.net/crl/complete.crl"}
	checkCollision(t, crls, names)

	crls2 := []string{"http://repository.com/crl",
		"http://repository.com/crl.crl",
		"http://crl.repository.com/",
		"http://crl.repository.com/crl"}
	checkCollision(t, crls2, names)

}

func makeCRL(t *testing.T, thisUpdate time.Time, nextUpdate time.Time) (*x509.Certificate, []byte) {
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Honest Achmed's Used Certificates and CRLs",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		t.Fatal(err)
	}

	ca, err := x509.ParseCertificate(caBytes)
	if err != nil {
		t.Fatal(err)
	}

	revokedCerts := []pkix.RevokedCertificate{}

	crlBytes, err := ca.CreateCRL(rand.Reader, caPrivKey, revokedCerts, thisUpdate, nextUpdate)
	if err != nil {
		t.Fatal(err)
	}

	return ca, crlBytes
}

func Test_loadAndCheckSignatureOfCRL(t *testing.T) {
	thisUpdate := time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)
	nextUpdate := time.Date(2020, time.February, 1, 0, 0, 0, 0, time.UTC)

	ca, crlBytes := makeCRL(t, thisUpdate, nextUpdate)

	crlPath, err := ioutil.TempFile("", "loadAndCheckSignatureOfCRL")
	if err != nil {
		t.Fatal(err)
	}

	defer os.Remove(crlPath.Name())

	if _, err := crlPath.Write(crlBytes); err != nil {
		t.Fatal(err)
	}
	if err := crlPath.Close(); err != nil {
		t.Fatal(err)
	}

	list, err := loadAndCheckSignatureOfCRL(crlPath.Name(), ca)
	if err != nil {
		t.Error(err)
	}

	if list.TBSCertList.ThisUpdate != thisUpdate {
		t.Error("This Update didn't match")
	}

	if list.TBSCertList.NextUpdate != nextUpdate {
		t.Error("This Update didn't match")
	}

	otherCa, _ := makeCRL(t, thisUpdate, nextUpdate)
	_, err = loadAndCheckSignatureOfCRL(crlPath.Name(), otherCa)
	if err == nil {
		t.Error("Should have failed")
	}

}
