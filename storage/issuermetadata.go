package storage

import (
	"encoding/json"
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
	filePath string
	backend  StorageBackend
}

// A separate type for future expandability
type Metadata struct {
	Crls      []*string `json:"crls"`
	IssuerDNs []*string `json:"issuerDNs"`
}

func NewIssuerMetadata(aMetadataPath string, aBackend StorageBackend) *IssuerMetadata {
	metadata := Metadata{
		Crls: make([]*string, 0, 10),
	}
	return &IssuerMetadata{
		mutex:    &sync.Mutex{},
		filePath: aMetadataPath,
		Metadata: metadata,
		backend:  aBackend,
	}
}

func (im *IssuerMetadata) Load() error {
	im.mutex.Lock()
	defer im.mutex.Unlock()

	data, err := im.backend.Load(im.filePath)
	if err != nil {
		glog.Errorf("Error reading issuer metadata %s: %s", im.filePath, err)
	}

	err = json.Unmarshal(data, &im.Metadata)
	if err != nil {
		glog.Errorf("Error unmarshaling issuer metadata %s: %s", im.filePath, err)
	}

	return err
}

func (im *IssuerMetadata) Save() error {
	im.mutex.Lock()
	defer im.mutex.Unlock()

	data, err := json.Marshal(im.Metadata)
	if err != nil {
		glog.Errorf("Error marshaling issuer metadata %s: %s", im.filePath, err)
	}

	err = im.backend.Store(im.filePath, data)
	if err != nil {
		glog.Errorf("Error storing issuer metadata %s: %s", im.filePath, err)
	}

	return err
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
		glog.V(3).Infof("[%s] CRL already known: %s (pos=%d)", im.filePath, url.String(), idx)
		return
	}

	// Non-allocating insert, see https://github.com/golang/go/wiki/SliceTricks
	glog.V(3).Infof("[%s] CRL unknown: %s (pos=%d)", im.filePath, url.String(), idx)
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
		glog.V(3).Infof("[%s] CRL already known: %s (pos=%d)", im.filePath, aIssuerDN, idx)
		return
	}

	// Non-allocating insert, see https://github.com/golang/go/wiki/SliceTricks
	glog.V(3).Infof("[%s] IssuerDN unknown: %s (pos=%d)", im.filePath, aIssuerDN, idx)
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
