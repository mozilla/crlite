package storage

import (
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/x509"
)

const kIssuers = "issuer"
const kCrls = "crl"

type IssuerMetadata struct {
	issuer         Issuer
	cache          RemoteCache
	mutex          *sync.RWMutex
	knownCrlDPs    map[string]struct{}
	knownIssuerDNs map[string]struct{}
	knownExpDates  map[string]struct{}
}

func NewIssuerMetadata(aIssuer Issuer, aCache RemoteCache) *IssuerMetadata {
	return &IssuerMetadata{
		issuer:         aIssuer,
		cache:          aCache,
		mutex:          &sync.RWMutex{},
		knownCrlDPs:    make(map[string]struct{}),
		knownIssuerDNs: make(map[string]struct{}),
		knownExpDates:  make(map[string]struct{}),
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

	result, err := im.cache.SortedInsert(im.crlId(), url.String())
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
	result, err := im.cache.SortedInsert(im.issuersId(), aIssuerDN)
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
// TODO: See which is faster, locking on these local caches, or just using extCache
// solely
func (im *IssuerMetadata) Accumulate(aCert *x509.Certificate) (bool, error) {
	expDate := aCert.NotAfter.Format(kExpirationFormat)
	dn := aCert.Issuer.String()
	im.mutex.RLock()
	_, seenExpDateBefore := im.knownExpDates[expDate]
	_, seenIssuerDn := im.knownIssuerDNs[dn]
	im.mutex.RUnlock()

	if !seenExpDateBefore {
		im.mutex.Lock()
		im.knownExpDates[expDate] = struct{}{}
		im.mutex.Unlock()

		cacheSeenBefore, err := im.cache.Exists(im.issuersId())
		if err != nil {
			return seenExpDateBefore, err
		}
		seenExpDateBefore = cacheSeenBefore
	}

	im.mutex.RLock()
	for _, dp := range aCert.CRLDistributionPoints {
		_, ok := im.knownCrlDPs[dp]

		if !ok {
			im.mutex.RUnlock()
			im.mutex.Lock()
			im.knownCrlDPs[dp] = struct{}{}
			im.mutex.Unlock()
			im.mutex.RLock()

			err := im.addCRL(dp)
			if err != nil {
				im.mutex.RUnlock()
				return seenExpDateBefore, err
			}
		}
	}
	im.mutex.RUnlock()

	if !seenIssuerDn {
		im.mutex.Lock()
		im.knownIssuerDNs[dn] = struct{}{}
		im.mutex.Unlock()
		return seenExpDateBefore, im.addIssuerDN(dn)
	}

	return seenExpDateBefore, nil
}

func (im *IssuerMetadata) Issuers() []string {
	strList, err := im.cache.SortedList(im.issuersId())
	if err != nil {
		glog.Fatalf("Error obtaining list of issuers: %v", err)
	}
	return strList
}

func (im *IssuerMetadata) CRLs() []string {
	strList, err := im.cache.SortedList(im.crlId())
	if err != nil {
		glog.Fatalf("Error obtaining list of CRLs: %v", err)
	}
	return strList
}
