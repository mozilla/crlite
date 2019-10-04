package storage

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/x509"
)

const kIssuers = "issuer"
const kCrls = "crl"

type IssuerMetadata struct {
	expDate string
	issuer  Issuer
	cache   RemoteCache
}

func NewIssuerMetadata(aExpDate string, aIssuer Issuer, aCache RemoteCache) *IssuerMetadata {
	return &IssuerMetadata{
		expDate: aExpDate,
		issuer:  aIssuer,
		cache:   aCache,
	}
}

func (im *IssuerMetadata) id() string {
	return fmt.Sprintf("%s::%s", im.expDate, im.issuer.ID())
}

func (im *IssuerMetadata) addCRL(aCRL string) error {
	url, err := url.Parse(strings.TrimSpace(aCRL))
	if err != nil {
		glog.Warningf("Not a valid CRL DP URL: %s %s", aCRL, err)
		return nil
	}

	if url.Scheme == "ldap" || url.Scheme == "ldaps" {
		return nil
	} else if url.Scheme != "http" && url.Scheme != "https" {
		glog.V(3).Infof("Ignoring unknown CRL scheme: %v", url)
		return nil
	}

	result, err := im.cache.SortedInsert(fmt.Sprintf("%s::%s", kCrls, im.id()), url.String())
	if err != nil {
		return err
	}

	if result {
		glog.V(3).Infof("[%s] CRL unknown: %s", im.id(), url.String())
	} else {
		glog.V(3).Infof("[%s] CRL already known: %s", im.id(), url.String())
	}
	return nil
}

func (im *IssuerMetadata) addIssuerDN(aIssuerDN string) error {
	result, err := im.cache.SortedInsert(fmt.Sprintf("%s::%s", kIssuers, im.id()), aIssuerDN)
	if err != nil {
		return err
	}

	if result {
		glog.V(3).Infof("[%s] IssuerDN unknown: %s", im.id(), aIssuerDN)
	} else {
		glog.V(3).Infof("[%s] IssuerDN already known: %s", im.id(), aIssuerDN)
	}
	return nil
}

// Must tolerate duplicate information
func (im *IssuerMetadata) Accumulate(aCert *x509.Certificate) (bool, error) {
	issuerSeenBefore, err := im.cache.Exists(fmt.Sprintf("%s::%s", kIssuers, im.id()))
	if err != nil {
		return issuerSeenBefore, err
	}

	for _, dp := range aCert.CRLDistributionPoints {
		err := im.addCRL(dp)
		if err != nil {
			return issuerSeenBefore, err
		}
	}

	issuerErr := im.addIssuerDN(aCert.Issuer.String())
	return issuerSeenBefore, issuerErr
}

func (im *IssuerMetadata) SetExpiryFlag() {
	expireTime, timeErr := time.ParseInLocation(kExpirationFormat, im.expDate, time.UTC)
	if timeErr != nil {
		glog.Errorf("Couldn't parse expiration time %s: %v", im.expDate, timeErr)
		return
	}

	if err := im.cache.ExpireAt(fmt.Sprintf("%s::%s", kIssuers, im.id()), expireTime); err != nil {
		glog.Errorf("Couldn't set expiration time %v for issuer %s: %v", expireTime, im.id(), err)
	}
	if err := im.cache.ExpireAt(fmt.Sprintf("%s::%s", kCrls, im.id()), expireTime); err != nil {
		glog.Errorf("Couldn't set expiration time %v for crl %s: %v", expireTime, im.id(), err)
	}
}

func (im *IssuerMetadata) Issuers() []string {
	strList, err := im.cache.SortedList(fmt.Sprintf("%s::%s", kIssuers, im.id()))
	if err != nil {
		glog.Fatalf("Error obtaining list of issuers: %v", err)
	}
	return strList
}

func (im *IssuerMetadata) CRLs() []string {
	strList, err := im.cache.SortedList(fmt.Sprintf("%s::%s", kCrls, im.id()))
	if err != nil {
		glog.Fatalf("Error obtaining list of CRLs: %v", err)
	}
	return strList
}
