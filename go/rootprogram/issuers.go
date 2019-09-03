package rootprogram

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/jcjones/ct-mapreduce/storage"
)

const (
	kMozCCADBReport = "https://ccadb-public.secure.force.com/mozilla/MozillaIntermediateCertsCSVReport"
)

type IssuerData struct {
	cert      *x509.Certificate
	subjectDN string
	pemInfo   string
	enrolled  bool
}

type EnrolledIssuer struct {
	PubKeyHash string `json:"pubKeyHash"`
	Whitelist  bool   `json:"whitelist"`
	Subject    string `json:"subject"`
	Pem        string `json:"pem"`
	Enrolled   bool   `json:"enrolled"`
}

type MozIssuers struct {
	issuerMap map[string]IssuerData
	mutex     *sync.Mutex
}

func NewMozillaIssuers() *MozIssuers {
	return &MozIssuers{mutex: &sync.Mutex{}}
}

func (mi *MozIssuers) Load() error {
	// TODO: Use a local cache
	return mi.downloadAndParse(kMozCCADBReport)
}

func (mi *MozIssuers) LoadFromDisk(aPath string) error {
	fd, err := os.Open(aPath)
	if err != nil {
		return err
	}
	defer fd.Close()
	return mi.parseCCADB(fd)
}

func (mi *MozIssuers) GetIssuers() []storage.Issuer {
	mi.mutex.Lock()
	defer mi.mutex.Unlock()

	issuers := make([]storage.Issuer, len(mi.issuerMap))
	i := 0

	for _, value := range mi.issuerMap {
		issuers[i] = storage.NewIssuer(value.cert)
		i++
	}
	return issuers
}

func (mi *MozIssuers) SaveIssuersList(filePath string) error {
	mi.mutex.Lock()
	defer mi.mutex.Unlock()
	enrolledCount := 0

	issuers := make([]EnrolledIssuer, len(mi.issuerMap))
	i := 0
	for _, val := range mi.issuerMap {
		pubKeyHash := sha256.Sum256(val.cert.RawSubjectPublicKeyInfo)
		issuers[i] = EnrolledIssuer{
			PubKeyHash: base64.URLEncoding.EncodeToString(pubKeyHash[:]),
			Whitelist:  false,
			Subject:    base64.URLEncoding.EncodeToString([]byte(val.subjectDN)),
			Pem:        val.pemInfo,
			Enrolled:   val.enrolled,
		}
		if val.enrolled {
			enrolledCount++
		}
		i++
	}

	glog.Infof("Saving %d issuers, of which %d are marked as enrolled", len(mi.issuerMap), enrolledCount)
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

func (mi *MozIssuers) GetCertificateForIssuer(aIssuer storage.Issuer) (*x509.Certificate, error) {
	mi.mutex.Lock()
	defer mi.mutex.Unlock()

	entry, ok := mi.issuerMap[aIssuer.ID()]
	if !ok {
		return nil, fmt.Errorf("Unknown issuer: %s", aIssuer.ID())
	}
	return entry.cert, nil
}

func (mi *MozIssuers) GetSubjectForIssuer(aIssuer storage.Issuer) (string, error) {
	mi.mutex.Lock()
	defer mi.mutex.Unlock()

	entry, ok := mi.issuerMap[aIssuer.ID()]
	if !ok {
		return "", fmt.Errorf("Unknown issuer: %s", aIssuer.ID())
	}
	return entry.subjectDN, nil
}

func decodeCertificateFromRow(aColMap map[string]int, aRow []string, aLineNum int) (*x509.Certificate, error) {
	p := strings.Trim(aRow[aColMap["PEM"]], "'")

	block, rest := pem.Decode([]byte(p))

	if block == nil {
		return nil, fmt.Errorf("Not a valid PEM at line %d", aLineNum)
	}

	if len(rest) != 0 {
		return nil, fmt.Errorf("Extra PEM data at line %d", aLineNum)
	}

	return x509.ParseCertificate(block.Bytes)
}

func (mi *MozIssuers) parseCCADB(aStream io.Reader) error {
	mi.mutex.Lock()
	defer mi.mutex.Unlock()

	mi.issuerMap = make(map[string]IssuerData, 0)

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

		issuer := storage.NewIssuer(cert)
		mi.issuerMap[issuer.ID()] = IssuerData{
			cert:      cert,
			subjectDN: cert.Subject.String(),
			pemInfo:   strings.Trim(row[columnMap["PEM"]], "'"),
			enrolled:  false,
		}
		lineNum += strings.Count(strings.Join(row, ""), "\n")
	}

	return nil
}

func (mi *MozIssuers) downloadAndParse(aUrl string) error {
	req, err := http.NewRequest("GET", aUrl, nil)
	if err != nil {
		return err
	}

	req.Header.Add("X-Automated-Tool", "https://github.com/mozilla/crlite")
	glog.Infof("Loading salesforce data from %s\n", aUrl)

	client := &http.Client{}
	r, err := client.Do(req)
	if err != nil {
		glog.Fatalf("Problem fetching salesforce data from URL %s\n", err)
	}

	defer r.Body.Close()
	return mi.parseCCADB(r.Body)
}
