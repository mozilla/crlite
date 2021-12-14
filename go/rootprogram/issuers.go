package rootprogram

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/mozilla/crlite/go/downloader"
	"github.com/mozilla/crlite/go/storage"
)

const (
	kMozCCADBReport = "https://ccadb-public.secure.force.com/mozilla/MozillaIntermediateCertsCSVReport"
)

type issuerCert struct {
	cert      *x509.Certificate
	subjectDN string
	pemInfo   string
}

type IssuerData struct {
	certs    []issuerCert
	enrolled bool
}

type EnrolledIssuer struct {
	PubKeyHash string `json:"pubKeyHash"`
	Whitelist  bool   `json:"whitelist"`
	SubjectDN  string `json:"subjectDN"`
	Subject    string `json:"subject"`
	Pem        string `json:"pem"`
	Enrolled   bool   `json:"enrolled"`
}

type MozIssuers struct {
	issuerMap map[string]IssuerData
	mutex     *sync.Mutex
	DiskPath  string
	ReportUrl string
	modTime   time.Time
}

func NewMozillaIssuers() *MozIssuers {
	return &MozIssuers{
		issuerMap: make(map[string]IssuerData, 0),
		mutex:     &sync.Mutex{},
		DiskPath:  fmt.Sprintf("%s/mozilla_issuers.csv", os.TempDir()),
		ReportUrl: kMozCCADBReport,
	}
}

type verifier struct {
}

func (v *verifier) IsValid(path string) error {
	mi := NewMozillaIssuers()
	return mi.LoadFromDisk(path)
}

type loggingAuditor struct{}

func (ta *loggingAuditor) FailedDownload(issuer downloader.DownloadIdentifier, crlUrl *url.URL,
	dlTracer *downloader.DownloadTracer, err error) {
	glog.Warningf("Failed download of %s: %s", crlUrl.String(), err)
}
func (ta *loggingAuditor) FailedVerifyUrl(issuer downloader.DownloadIdentifier, crlUrl *url.URL,
	dlTracer *downloader.DownloadTracer, err error) {
	glog.Warningf("Failed verify of %s: %s", crlUrl.String(), err)
}
func (ta *loggingAuditor) FailedVerifyPath(issuer downloader.DownloadIdentifier, crlUrl *url.URL, crlPath string,
	err error) {
	glog.Warningf("Failed verify of %s (local: %s): %s", crlUrl.String(), crlPath, err)
}

type identifier struct{}

func (i *identifier) ID() string {
	return "Mozilla Issuers"
}

func (mi *MozIssuers) Load() error {
	ctx := context.Background()

	dataUrl, err := url.Parse(mi.ReportUrl)
	if err != nil {
		glog.Fatalf("Couldn't parse CCADB URL of %s: %s", mi.ReportUrl, err)
		return err
	}

	isAcceptable, err := downloader.DownloadAndVerifyFileSync(ctx, &verifier{}, &loggingAuditor{}, &identifier{},
		*dataUrl, mi.DiskPath, 3, 300*time.Second)

	if !isAcceptable {
		return err
	}

	if err != nil {
		glog.Warningf("Error encountered loading CCADB data, but able to proceed with previous data. Error: %s", err)
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
	mi.modTime = fi.ModTime()
	return mi.parseCCADB(fd)
}

func (mi *MozIssuers) DatasetAge() time.Duration {
	if mi.modTime.IsZero() {
		return 0
	}
	return time.Since(mi.modTime)
}

func (mi *MozIssuers) GetIssuers() []storage.Issuer {
	mi.mutex.Lock()
	defer mi.mutex.Unlock()

	issuers := make([]storage.Issuer, len(mi.issuerMap))
	i := 0

	for _, value := range mi.issuerMap {
		cert := value.certs[0].cert
		issuers[i] = storage.NewIssuer(cert)
		i++
	}
	return issuers
}

func (mi *MozIssuers) SaveIssuersList(filePath string) error {
	mi.mutex.Lock()
	defer mi.mutex.Unlock()
	enrolledCount := 0
	certCount := 0

	issuers := make([]EnrolledIssuer, 0, len(mi.issuerMap))
	for _, val := range mi.issuerMap {
		for _, cert := range val.certs {
			pubKeyHash := sha256.Sum256(cert.cert.RawSubjectPublicKeyInfo)
			issuers = append(issuers, EnrolledIssuer{
				PubKeyHash: base64.URLEncoding.EncodeToString(pubKeyHash[:]),
				Whitelist:  false,
				SubjectDN:  base64.URLEncoding.EncodeToString([]byte(cert.subjectDN)),
				Subject:    cert.subjectDN,
				Pem:        cert.pemInfo,
				Enrolled:   val.enrolled,
			})
			certCount++
			if val.enrolled {
				enrolledCount++
			}
		}
	}

	glog.Infof("Saving %d issuers and %d certs, of which %d are marked as enrolled", len(mi.issuerMap), certCount, enrolledCount)
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
		cert, err := decodeCertificateFromPem(ei.Pem)
		if err != nil {
			return err
		}
		issuer := mi.InsertIssuerFromCertAndPem(cert, ei.Pem)
		if ei.Enrolled {
			mi.Enroll(issuer)
		}
		// TODO: Support whitelisting, overall
	}

	return nil
}

func (mi *MozIssuers) Enroll(aIssuer storage.Issuer) {
	mi.mutex.Lock()
	defer mi.mutex.Unlock()

	if _, ok := mi.issuerMap[aIssuer.ID()]; ok {
		data := mi.issuerMap[aIssuer.ID()]
		data.enrolled = true
		mi.issuerMap[aIssuer.ID()] = data
	}
}

func (mi *MozIssuers) IsIssuerInProgram(aIssuer storage.Issuer) bool {
	_, ok := mi.issuerMap[aIssuer.ID()]
	return ok
}

func (mi *MozIssuers) IsIssuerEnrolled(aIssuer storage.Issuer) bool {
	if _, ok := mi.issuerMap[aIssuer.ID()]; ok {
		data := mi.issuerMap[aIssuer.ID()]
		return data.enrolled
	}
	return false
}

func (mi *MozIssuers) GetCertificateForIssuer(aIssuer storage.Issuer) (*x509.Certificate, error) {
	mi.mutex.Lock()
	defer mi.mutex.Unlock()

	entry, ok := mi.issuerMap[aIssuer.ID()]
	if !ok {
		return nil, fmt.Errorf("Unknown issuer: %s", aIssuer.ID())
	}
	return entry.certs[0].cert, nil
}

func (mi *MozIssuers) GetSubjectForIssuer(aIssuer storage.Issuer) (string, error) {
	mi.mutex.Lock()
	defer mi.mutex.Unlock()

	entry, ok := mi.issuerMap[aIssuer.ID()]
	if !ok {
		return "", fmt.Errorf("Unknown issuer: %s", aIssuer.ID())
	}
	return entry.certs[0].subjectDN, nil
}

func decodeCertificateFromPem(aPem string) (*x509.Certificate, error) {
	block, rest := pem.Decode([]byte(aPem))

	if block == nil {
		return nil, fmt.Errorf("Not a valid PEM")
	}

	if len(rest) != 0 {
		return nil, fmt.Errorf("Extra PEM data")
	}

	return x509.ParseCertificate(block.Bytes)
}

func decodeCertificateFromRow(aColMap map[string]int, aRow []string, aLineNum int) (*x509.Certificate, error) {
	p := strings.Trim(aRow[aColMap["PEM"]], "'")

	cert, err := decodeCertificateFromPem(p)
	if err != nil {
		return nil, fmt.Errorf("%s at line %d", err, aLineNum)
	}
	return cert, nil
}

func (mi *MozIssuers) InsertIssuerFromCertAndPem(aCert *x509.Certificate, aPem string) storage.Issuer {
	issuer := storage.NewIssuer(aCert)
	ic := issuerCert{
		cert:      aCert,
		subjectDN: aCert.Subject.String(),
		pemInfo:   aPem,
	}

	v, exists := mi.issuerMap[issuer.ID()]
	if exists {
		glog.V(1).Infof("[%s] Duplicate issuer ID: %v with %v", issuer.ID(), v, aCert.Subject.String())
		v.certs = append(v.certs, ic)
		mi.issuerMap[issuer.ID()] = v
		return issuer
	}

	mi.issuerMap[issuer.ID()] = IssuerData{
		certs:    []issuerCert{ic},
		enrolled: false,
	}
	return issuer
}

func (mi *MozIssuers) NewTestIssuerFromSubjectString(aSub string) storage.Issuer {
	issuer := storage.NewIssuerFromString(aSub)
	ic := issuerCert{
		subjectDN: aSub,
	}
	mi.issuerMap[issuer.ID()] = IssuerData{
		certs:    []issuerCert{ic},
		enrolled: false,
	}
	return issuer
}

func (mi *MozIssuers) parseCCADB(aStream io.Reader) error {
	mi.mutex.Lock()
	defer mi.mutex.Unlock()

	reader := csv.NewReader(aStream)
	columnMap := make(map[string]int)
	columns, err := reader.Read()
	if err != nil {
		return err
	}

	for index, attr := range columns {
		columnMap[attr] = index
	}

	lineNum := 1
	for row, err := reader.Read(); err == nil; row, err = reader.Read() {
		lineNum += 1

		cert, err := decodeCertificateFromRow(columnMap, row, lineNum)
		if err != nil {
			return err
		}

		_ = mi.InsertIssuerFromCertAndPem(cert, strings.Trim(row[columnMap["PEM"]], "'"))
		lineNum += strings.Count(strings.Join(row, ""), "\n")
	}

	return nil
}
