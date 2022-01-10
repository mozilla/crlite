package storage

import (
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/mozilla/crlite/go"
)

const kIssuers = "issuer"
const kCrls = "crl"

type IssuerMetadata struct {
	issuer         types.Issuer
	cache          RemoteCache
	mutex          *sync.RWMutex
	knownCrlDPs    map[string]struct{}
	knownIssuerDNs map[string]struct{}
}

func NewIssuerMetadata(aIssuer types.Issuer, aCache RemoteCache) *IssuerMetadata {
	return &IssuerMetadata{
		issuer:         aIssuer,
		cache:          aCache,
		mutex:          &sync.RWMutex{},
		knownCrlDPs:    make(map[string]struct{}),
		knownIssuerDNs: make(map[string]struct{}),
	}
}

func (im *IssuerMetadata) id() string {
	return im.issuer.ID()
}

func (im *IssuerMetadata) crlId() string {
	return fmt.Sprintf("%s::%s", kCrls, im.id())
}

func (im *IssuerMetadata) issuersId() string {
	return fmt.Sprintf("%s::%s", kIssuers, im.id())
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

	result, err := im.cache.SetInsert(im.crlId(), url.String())
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
	result, err := im.cache.SetInsert(im.issuersId(), aIssuerDN)
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

// Check if the certificate contains any novel CRLs or issuer DNs
func (im *IssuerMetadata) ShouldStoreMetadata(aCert *x509.Certificate) bool {
	dn := aCert.Issuer.String()
	dps := aCert.CRLDistributionPoints
	foundNew := false

	im.mutex.RLock()
	defer im.mutex.RUnlock()

	_, seenIssuerDn := im.knownIssuerDNs[dn]
	foundNew = foundNew || !seenIssuerDn

	for _, dp := range dps {
		_, seenCrlDp := im.knownCrlDPs[dp]
		foundNew = foundNew || !seenCrlDp
	}

	return foundNew
}

// Store CRL and Issuer records
func (im *IssuerMetadata) Accumulate(aCert *x509.Certificate) error {

	if !im.ShouldStoreMetadata(aCert) {
		return nil
	}

	dn := aCert.Issuer.String()
	dps := aCert.CRLDistributionPoints

	im.mutex.Lock()
	defer im.mutex.Unlock()

	_, seenIssuerDn := im.knownIssuerDNs[dn]
	if !seenIssuerDn {
		err := im.addIssuerDN(dn)
		if err != nil {
			return fmt.Errorf("Could not add DN for issuer %s: %v", im.id(), err)
		}
		im.knownIssuerDNs[dn] = struct{}{}
	}

	for _, dp := range dps {
		_, seenCrlDp := im.knownCrlDPs[dp]
		if !seenCrlDp {
			err := im.addCRL(dp)
			if err != nil {
				return fmt.Errorf("Could not add CRL for issuer %s: %v", im.id(), err)
			}
			im.knownCrlDPs[dp] = struct{}{}
		}
	}

	return nil
}

func (im *IssuerMetadata) Issuers() []string {
	strList, err := im.cache.SetList(im.issuersId())
	if err != nil {
		glog.Fatalf("Error obtaining list of issuers: %v", err)
	}
	return strList
}

func (im *IssuerMetadata) CRLs() []string {
	strList, err := im.cache.SetList(im.crlId())
	if err != nil {
		glog.Fatalf("Error obtaining list of CRLs: %v", err)
	}
	return strList
}
