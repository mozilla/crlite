package storage

import (
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/x509"
)

type IssuerMetadata struct {
	mutex    *sync.Mutex
	Metadata Metadata
	expDate  string
	issuer   Issuer
	backend  StorageBackend
}

// A separate type for future expandability
type Metadata struct {
	Crls      []*string `json:"crls"`
	IssuerDNs []*string `json:"issuerDNs"`
}

func NewIssuerMetadata(aExpDate string, aIssuer Issuer, aBackend StorageBackend) *IssuerMetadata {
	metadata := Metadata{
		Crls:      []*string{},
		IssuerDNs: []*string{},
	}
	return &IssuerMetadata{
		mutex:    &sync.Mutex{},
		expDate:  aExpDate,
		issuer:   aIssuer,
		Metadata: metadata,
		backend:  aBackend,
	}
}

func (im *IssuerMetadata) id() string {
	return im.expDate + "::" + im.issuer.ID()
}

func (im *IssuerMetadata) Load() error {
	im.mutex.Lock()
	defer im.mutex.Unlock()

	data, err := im.backend.LoadIssuerMetadata(im.expDate, im.issuer)
	if err != nil {
		return err
	}

	im.Metadata = *data
	return nil
}

func (im *IssuerMetadata) Save() error {
	im.mutex.Lock()
	defer im.mutex.Unlock()

	return im.backend.StoreIssuerMetadata(im.expDate, im.issuer, &im.Metadata)
}

func (im *IssuerMetadata) addCRL(aCRL string) {
	// Assume that im.mutex is locked
	count := len(im.Metadata.Crls)

	url, err := url.Parse(strings.TrimSpace(aCRL))
	if err != nil {
		glog.Warningf("Not a valid CRL DP URL: %s %s", aCRL, err)
		return
	}

	if url.Scheme == "ldap" || url.Scheme == "ldaps" {
		return
	} else if url.Scheme != "http" && url.Scheme != "https" {
		glog.V(3).Infof("Ignoring unknown CRL scheme: %v", url)
		return
	}

	idx := sort.Search(count, func(i int) bool {
		return strings.Compare(url.String(), *im.Metadata.Crls[i]) <= 0
	})

	var cmp int
	if idx < count {
		cmp = strings.Compare(url.String(), *im.Metadata.Crls[idx])
	}

	if idx < count && cmp == 0 {
		glog.V(3).Infof("[%s] CRL already known: %s (pos=%d)", im.id(), url.String(), idx)
		return
	}

	// Non-allocating insert, see https://github.com/golang/go/wiki/SliceTricks
	glog.V(3).Infof("[%s] CRL unknown: %s (pos=%d)", im.id(), url.String(), idx)
	im.Metadata.Crls = append(im.Metadata.Crls, nil)
	copy(im.Metadata.Crls[idx+1:], im.Metadata.Crls[idx:])
	sanitizedCRL := url.String()
	im.Metadata.Crls[idx] = &sanitizedCRL
}

func (im *IssuerMetadata) addIssuerDN(aIssuerDN string) {
	// Assume that im.mutex is locked
	count := len(im.Metadata.IssuerDNs)

	idx := sort.Search(count, func(i int) bool {
		return strings.Compare(aIssuerDN, *im.Metadata.IssuerDNs[i]) <= 0
	})

	var cmp int
	if idx < count {
		cmp = strings.Compare(aIssuerDN, *im.Metadata.IssuerDNs[idx])
	}

	if idx < count && cmp == 0 {
		glog.V(3).Infof("[%s] CRL already known: %s (pos=%d)", im.id(), aIssuerDN, idx)
		return
	}

	// Non-allocating insert, see https://github.com/golang/go/wiki/SliceTricks
	glog.V(3).Infof("[%s] IssuerDN unknown: %s (pos=%d)", im.id(), aIssuerDN, idx)
	im.Metadata.IssuerDNs = append(im.Metadata.IssuerDNs, nil)
	copy(im.Metadata.IssuerDNs[idx+1:], im.Metadata.IssuerDNs[idx:])
	im.Metadata.IssuerDNs[idx] = &aIssuerDN
}

// Must tolerate duplicate information
func (im *IssuerMetadata) Accumulate(aCert *x509.Certificate) {
	im.mutex.Lock()
	defer im.mutex.Unlock()

	for _, dp := range aCert.CRLDistributionPoints {
		im.addCRL(dp)
	}

	im.addIssuerDN(aCert.Issuer.String())
}
