package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io/ioutil"
	"math/big"
	"net/url"
	"os"
	"strings"
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

func makeCA(t *testing.T) (*x509.Certificate, interface{}) {
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

	return ca, caPrivKey
}

func makeCRL(t *testing.T, ca *x509.Certificate, caPrivKey interface{}, thisUpdate time.Time, nextUpdate time.Time) []byte {
	revokedCerts := []pkix.RevokedCertificate{}

	crlBytes, err := ca.CreateCRL(rand.Reader, caPrivKey, revokedCerts, thisUpdate, nextUpdate)
	if err != nil {
		t.Fatal(err)
	}

	return crlBytes
}

func Test_loadAndCheckSignatureOfCRL(t *testing.T) {
	thisUpdate := time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)
	nextUpdate := time.Date(2020, time.February, 1, 0, 0, 0, 0, time.UTC)

	ca, caPrivKey := makeCA(t)

	crlBytes := makeCRL(t, ca, caPrivKey, thisUpdate, nextUpdate)

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

	otherCa, _ := makeCA(t)
	_, err = loadAndCheckSignatureOfCRL(crlPath.Name(), otherCa)
	if !strings.Contains(err.Error(), "verification failure") {
		t.Error(err)
	}
}

func Test_verifyCRL(t *testing.T) {
	todayThisUpdate := time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)
	todayNextUpdate := time.Date(2020, time.February, 1, 0, 0, 0, 0, time.UTC)

	ca, caPrivKey := makeCA(t)

	todayCrlBytes := makeCRL(t, ca, caPrivKey, todayThisUpdate, todayNextUpdate)
	todayCrlPath, err := ioutil.TempFile("", "todays_crl")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(todayCrlPath.Name())
	if _, err := todayCrlPath.Write(todayCrlBytes); err != nil {
		t.Fatal(err)
	}
	if err := todayCrlPath.Close(); err != nil {
		t.Fatal(err)
	}

	// Prompt the case where yesterday's was newer than today's
	yesterdayThisUpdate := time.Date(2020, time.January, 2, 0, 0, 0, 0, time.UTC)
	yesterdayNextUpdate := time.Date(2020, time.February, 2, 0, 0, 0, 0, time.UTC)

	yesterdayCrlBytes := makeCRL(t, ca, caPrivKey, yesterdayThisUpdate, yesterdayNextUpdate)
	yesterdayCrlPath, err := ioutil.TempFile("", "yesterdays_crl")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(yesterdayCrlPath.Name())
	if _, err := yesterdayCrlPath.Write(yesterdayCrlBytes); err != nil {
		t.Fatal(err)
	}
	if err := yesterdayCrlPath.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = verifyCRL(todayCrlPath.Name(), ca, yesterdayCrlPath.Name())
	if !strings.Contains(err.Error(), "CRL is older than the previous CRL") {
		t.Error(err)
	}

	// Should work fine this orientation
	list, err := verifyCRL(yesterdayCrlPath.Name(), ca, todayCrlPath.Name())
	if err != nil {
		t.Error(err)
	}
	if list.TBSCertList.ThisUpdate != yesterdayThisUpdate {
		t.Error("This Update didn't match")
	}

	if list.TBSCertList.NextUpdate != yesterdayNextUpdate {
		t.Error("This Update didn't match")
	}

	_, otherCaPrivKey := makeCA(t)

	// Prompt the case where yesterday's is OK but today's is mis-signed
	todayOtherSignerCrlBytes := makeCRL(t, ca, otherCaPrivKey, todayThisUpdate, todayNextUpdate)
	todayOtherSignerCrlPath, err := ioutil.TempFile("", "todays_other_signer_crl")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(todayOtherSignerCrlPath.Name())
	if _, err := todayOtherSignerCrlPath.Write(todayOtherSignerCrlBytes); err != nil {
		t.Fatal(err)
	}
	if err := todayOtherSignerCrlPath.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = verifyCRL(todayOtherSignerCrlPath.Name(), ca, yesterdayCrlPath.Name())
	if !strings.Contains(err.Error(), "verification failure") {
		t.Error(err)
	}

}
