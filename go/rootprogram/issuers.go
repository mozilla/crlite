package rootprogram

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang/glog"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	zcx509 "github.com/zmap/zcrypto/x509"

	"github.com/mozilla/crlite/go"
	"github.com/mozilla/crlite/go/downloader"
)

const (
	kMozCCADBReport = "https://ccadb.my.salesforce-sites.com/ccadb/Report?Name=MozillaAllUnexpiredPEMs"
)

type issuerCert struct {
	cert      *ctx509.Certificate
	subjectDN string
	pemInfo   string
}

type IssuerData struct {
	certs               []issuerCert
	usesPartitionedCrls bool
}

type EnrolledIssuer struct {
	UniqueID            string `json:"uniqueID"`
	PubKeyHash          string `json:"pubKeyHash"`
	Subject             string `json:"subject"`
	Pem                 string `json:"pem"`
	UsesPartitionedCrls bool   `json:"usesPartitionedCrls"`
}

type MozIssuers struct {
	issuerMap map[string]IssuerData
	CrlMap    types.IssuerCrlMap
	mutex     *sync.Mutex
	DiskPath  string
	ReportUrl string
	modTime   time.Time
}

func NewMozillaIssuers() *MozIssuers {
	return &MozIssuers{
		issuerMap: make(map[string]IssuerData, 0),
		CrlMap:    make(types.IssuerCrlMap, 0),
		mutex:     &sync.Mutex{},
		DiskPath:  fmt.Sprintf("%s/mozilla_all_unexpired_pems.csv", os.TempDir()),
		ReportUrl: kMozCCADBReport,
	}
}

func (mi *MozIssuers) Load() error {
	ctx := context.Background()

	err := mi.LoadFromDisk(mi.DiskPath)
	if err == nil && mi.DatasetAge() < 12*time.Hour {
		return nil
	}

	dataUrl, err := url.Parse(mi.ReportUrl)
	if err != nil {
		glog.Fatalf("Couldn't parse CCADB URL of %s: %s", mi.ReportUrl, err)
		return err
	}

	err = downloader.DownloadFileSync(ctx, *dataUrl, mi.DiskPath, 3, 300*time.Second)
	if err != nil {
		glog.Errorf("Error downloading CCADB report: %s", err)
		return err
	}

	return mi.LoadFromDisk(mi.DiskPath)
}

func (mi *MozIssuers) LoadFromDisk(aPath string) error {
	fd, err := os.Open(aPath)
	if err != nil {
		return err
	}
	defer fd.Close()

	fi, err := os.Stat(aPath)
	if err != nil {
		return err
	}

	reader := csv.NewReader(fd)
	columns, err := reader.Read()
	if err != nil {
		return err
	}

	columnMap := make(map[string]int)
	for index, attr := range columns {
		columnMap[attr] = index
	}

	requiredColumns := []string{
		"X.509_Certificate_PEM",
		"RecordType.Name",
		"Revocation_Status__c",
		"Full_CRL_Issued_By_This_CA",
		"JSON_Array_of_Partitioned_CRLs",
	}
	for _, s := range requiredColumns {
		_, exists := columnMap[s]
		if !exists {
			return fmt.Errorf("%s column not found", s)
		}
	}

	metadataRecords, err := reader.ReadAll()
	if err != nil {
		return err
	}

	mi.mutex.Lock()
	defer mi.mutex.Unlock()
	mi.modTime = fi.ModTime()

	intermediateCerts := make(map[string]*zcx509.Certificate)
	intermediateCRLs := make(map[string][]string)
	usesPartitioned := make(map[string]bool)

	mozillaRootPool := zcx509.NewCertPool()
	intermediatePool := zcx509.NewCertPool()

	mozillaRootCount := 0
	intermediateCount := 0

	for _, row := range metadataRecords {
		if len(row) < len(columnMap) {
			continue
		}

		cert, err := PEMToZcryptoCertificate(row[columnMap["X.509_Certificate_PEM"]])
		if err != nil {
			glog.Warningf("Failed to parse certificate in row %d: %s", row, err)
			continue
		}

		fp := CertificateFingerprint(cert)

		certType := row[columnMap["RecordType.Name"]]
		revoked := row[columnMap["Revocation_Status__c"]]
		fullCrl := row[columnMap["Full_CRL_Issued_By_This_CA"]]
		jsonArrayOfCrls := row[columnMap["JSON_Array_of_Partitioned_CRLs"]]

		if revoked != "Not Revoked" && revoked != "" {
			continue
		}

		if certType == "Root Certificate" {
			mozillaRootPool.AddCert(cert)
			mozillaRootCount += 1
			continue
		}

		if certType == "Intermediate Certificate" {
			_, duplicate := intermediateCerts[fp]
			if duplicate {
				glog.Warningf("Duplicate certificate in row %d", row)
				continue
			}

			intermediatePool.AddCert(cert)
			intermediateCerts[fp] = cert
			intermediateCount += 1

			crls, partitioned, err := decodeCrls(fullCrl, jsonArrayOfCrls)
			if err == nil {
				intermediateCRLs[fp] = crls
				usesPartitioned[fp] = partitioned
			}
		}
	}

	glog.Infof("Found %d Mozilla roots", mozillaRootCount)
	glog.Infof("Found %d valid intermediate candidates", intermediateCount)

	verifyOpts := zcx509.VerifyOptions{
		Roots:         mozillaRootPool,
		Intermediates: intermediatePool,
		CurrentTime:   time.Now(),
		KeyUsages:     []zcx509.ExtKeyUsage{zcx509.ExtKeyUsageServerAuth},
	}

	validCount := 0
	for fp, zcCert := range intermediateCerts {
		chains, _, _, err := zcCert.Verify(verifyOpts)
		if err == nil && len(chains) > 0 {
			ctCert, err := ZcryptoToCtCertificate(zcCert)
			if err != nil {
				glog.Warningf("Failed to convert certificate %s: %v", fp, err)
				continue
			}
			crls := intermediateCRLs[fp]
			partitioned := usesPartitioned[fp]
			mi.InsertIssuer(ctCert, crls, partitioned)
			validCount++
		}
	}

	glog.Infof("Found %d intermediates that chain to Mozilla roots", validCount)
	return nil
}

func (mi *MozIssuers) DatasetAge() time.Duration {
	if mi.modTime.IsZero() {
		return 0
	}
	return time.Since(mi.modTime)
}

func (mi *MozIssuers) GetIssuers() []types.Issuer {
	mi.mutex.Lock()
	defer mi.mutex.Unlock()

	issuers := make([]types.Issuer, len(mi.issuerMap))
	i := 0

	for _, value := range mi.issuerMap {
		cert := value.certs[0].cert
		issuers[i] = types.NewIssuer(cert)
		i++
	}
	return issuers
}

func CertificateToPEM(cert *ctx509.Certificate) string {
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	return strings.TrimSpace(string(pem.EncodeToMemory(pemBlock)))
}

func PEMToCertificate(aPem string) (*ctx509.Certificate, error) {
	block, _ := pem.Decode([]byte(aPem))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("PEM block type is %s, expected CERTIFICATE", block.Type)
	}

	cert, err := ctx509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

func PEMToZcryptoCertificate(aPem string) (*zcx509.Certificate, error) {
	block, _ := pem.Decode([]byte(aPem))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("PEM block type is %s, expected CERTIFICATE", block.Type)
	}

	cert, err := zcx509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

func ZcryptoToCtCertificate(zcCert *zcx509.Certificate) (*ctx509.Certificate, error) {
	ctCert, err := ctx509.ParseCertificate(zcCert.Raw)
	if err != nil {
		return nil, fmt.Errorf("failed to convert certificate: %w", err)
	}
	return ctCert, nil
}

func CertificateFingerprint(cert *zcx509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return strings.ToUpper(hex.EncodeToString(hash[:]))
}

func (mi *MozIssuers) SaveIssuersList(filePath string) error {
	mi.mutex.Lock()
	defer mi.mutex.Unlock()
	certCount := 0

	issuers := make([]EnrolledIssuer, 0, len(mi.issuerMap))
	for _, val := range mi.issuerMap {
		for _, cert := range val.certs {
			pubKeyHash := sha256.Sum256(cert.cert.RawSubjectPublicKeyInfo)
			uniqueID := sha256.Sum256(append(cert.cert.RawSubject, cert.cert.RawSubjectPublicKeyInfo...))
			issuers = append(issuers, EnrolledIssuer{
				UniqueID:            base64.URLEncoding.EncodeToString(uniqueID[:]),
				PubKeyHash:          base64.URLEncoding.EncodeToString(pubKeyHash[:]),
				Subject:             cert.subjectDN,
				Pem:                 CertificateToPEM(cert.cert),
				UsesPartitionedCrls: val.usesPartitionedCrls,
			})
			certCount++
		}
	}

	glog.Infof("Saving %d issuers and %d certs", len(mi.issuerMap), certCount)
	fd, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		glog.Errorf("Error opening enrolled issuer %s: %s", filePath, err)
		return err
	}

	enc := json.NewEncoder(fd)

	if err := enc.Encode(issuers); err != nil {
		glog.Errorf("Error marshaling enrolled issuer %s: %s", filePath, err)
	}

	if err = fd.Close(); err != nil {
		glog.Errorf("Error storing enrolled issuer %s: %s", filePath, err)
	}

	return err
}

func (mi *MozIssuers) LoadEnrolledIssuers(filePath string) error {
	bytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	list := make([]EnrolledIssuer, 0)
	err = json.Unmarshal(bytes, &list)
	if err != nil {
		return err
	}

	for _, ei := range list {
		cert, err := PEMToCertificate(ei.Pem)
		if err != nil {
			return err
		}
		mi.InsertIssuer(cert, nil, ei.UsesPartitionedCrls)
	}

	return nil
}

func (mi *MozIssuers) IsIssuerInProgram(aIssuer types.Issuer) bool {
	_, ok := mi.issuerMap[aIssuer.ID()]
	return ok
}

func (mi *MozIssuers) GetCertificateForIssuer(aIssuer types.Issuer) (*ctx509.Certificate, error) {
	mi.mutex.Lock()
	defer mi.mutex.Unlock()

	entry, ok := mi.issuerMap[aIssuer.ID()]
	if !ok {
		return nil, fmt.Errorf("Unknown issuer: %s", aIssuer.ID())
	}
	return entry.certs[0].cert, nil
}

func (mi *MozIssuers) GetSubjectForIssuer(aIssuer types.Issuer) (string, error) {
	mi.mutex.Lock()
	defer mi.mutex.Unlock()

	entry, ok := mi.issuerMap[aIssuer.ID()]
	if !ok {
		return "", fmt.Errorf("Unknown issuer: %s", aIssuer.ID())
	}
	return entry.certs[0].subjectDN, nil
}

func (mi *MozIssuers) GetUsesPartitionedCrlsForIssuer(aIssuer types.Issuer) (bool, error) {
	mi.mutex.Lock()
	defer mi.mutex.Unlock()

	entry, ok := mi.issuerMap[aIssuer.ID()]
	if !ok {
		return false, fmt.Errorf("Unknown issuer: %s", aIssuer.ID())
	}
	return entry.usesPartitionedCrls, nil
}

func decodeCrls(fullCrlStr string, partCrlJson string) ([]string, bool, error) {
	usesPartitionedCrls := false
	crls := []string{}
	fullCrlStr = strings.Trim(strings.TrimSpace(fullCrlStr), `"`)
	if fullCrlStr != "" {
		fullCrlUrl, err := url.Parse(fullCrlStr)
		if err != nil {
			glog.Warningf("decodeCrls: Could not parse %q as URL: %v", fullCrlStr, err)
		} else if fullCrlUrl.Scheme != "http" && fullCrlUrl.Scheme != "https" {
			glog.Warningf("decodeCrls: Unknown URL scheme in %q", fullCrlUrl.String())
		} else {
			crls = append(crls, fullCrlUrl.String())
		}
	}

	partCrlJson = strings.Trim(strings.TrimSpace(partCrlJson), "[]")
	partCrls := strings.Split(partCrlJson, ",")
	for _, crl := range partCrls {
		crl = strings.Trim(strings.TrimSpace(crl), `"`)
		if crl == "" {
			continue
		}

		// If an issuer has populated its "JSON Array of Partitioned
		// CRLs" field, then we need to validate the
		// issuingDistributionPoint extension in each of its CRLs. If
		// we've gotten here then there is at least one entry in the
		// JSON Array field.
		usesPartitionedCrls = true

		crlUrl, err := url.Parse(crl)
		if err != nil {
			glog.Warningf("decodeCrls: Could not parse %q as URL: %v", crl, err)
		} else if crlUrl.Scheme != "http" && crlUrl.Scheme != "https" {
			glog.Warningf("decodeCrls: Unknown URL scheme in %q", crlUrl.String())
		} else {
			crls = append(crls, crlUrl.String())
		}
	}

	return crls, usesPartitionedCrls, nil
}

func (mi *MozIssuers) InsertIssuer(aCert *ctx509.Certificate, aCrls []string, aUsesPartitionedCrls bool) types.Issuer {
	issuer := types.NewIssuer(aCert)
	ic := issuerCert{
		cert:      aCert,
		subjectDN: aCert.Subject.String(),
		pemInfo:   CertificateToPEM(aCert),
	}

	crlSet, exists := mi.CrlMap[issuer.ID()]
	if !exists {
		crlSet = make(map[string]bool, 0)
	}
	for _, crl := range aCrls {
		crlSet[crl] = true
	}
	mi.CrlMap[issuer.ID()] = crlSet

	v, exists := mi.issuerMap[issuer.ID()]
	if exists {
		v.certs = append(v.certs, ic)
		mi.issuerMap[issuer.ID()] = v
		return issuer
	}

	mi.issuerMap[issuer.ID()] = IssuerData{
		certs:               []issuerCert{ic},
		usesPartitionedCrls: aUsesPartitionedCrls,
	}

	return issuer
}

func (mi *MozIssuers) NewTestIssuerFromSubjectString(aSub string) types.Issuer {
	issuer := types.NewIssuerFromString(aSub)
	ic := issuerCert{
		subjectDN: aSub,
	}
	mi.issuerMap[issuer.ID()] = IssuerData{
		certs: []issuerCert{ic},
	}
	return issuer
}
