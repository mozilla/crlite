package main

import (
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/x509"
)

const (
	kMozCCADBReport = "https://ccadb-public.secure.force.com/mozilla/PublicAllInterCertsIncTechConsWithPEMCSV"
)

var (
	outfile = flag.String("out", "<stdout>", "output json dictionary of issuers")
	incsv   = flag.String("in", "<path>", "input CCADB CSV path")
)

func decodeCertificateFromRow(aColMap map[string]int, aRow []string, aLineNum int) (*x509.Certificate, error) {
	p := strings.Trim(aRow[aColMap["PEM Info"]], "'")

	block, rest := pem.Decode([]byte(p))

	if block == nil {
		return nil, fmt.Errorf("Not a valid PEM at line %d", aLineNum)
	}

	if len(rest) != 0 {
		return nil, fmt.Errorf("Extra PEM data at line %d", aLineNum)
	}

	return x509.ParseCertificate(block.Bytes)
}

func parseCCADB(aStream io.Reader) ([]string, error) {
	records := make([]string, 0)

	reader := csv.NewReader(aStream)
	columnMap := make(map[string]int)
	columns, err := reader.Read()
	if err != nil {
		return records, err
	}

	for index, attr := range columns {
		columnMap[attr] = index
	}

	lineNum := 1
	for row, err := reader.Read(); err == nil; row, err = reader.Read() {
		lineNum += 1

		cert, err := decodeCertificateFromRow(columnMap, row, lineNum)
		if err != nil {
			return records, err
		}

		issuerID := base64.URLEncoding.EncodeToString(cert.AuthorityKeyId)

		records = append(records, issuerID)
		lineNum += strings.Count(strings.Join(row, ""), "\n")
	}

	return records, nil
}

func downloadAndParse(aUrl string) ([]string, error) {
	req, err := http.NewRequest("GET", aUrl, nil)
	if err != nil {
		return []string{}, err
	}
	req.Header.Add("X-Automated-Tool", "https://github.com/mozilla/crlite/cmd/get-mozilla-issuers")
	glog.Infof("Loading salesforce data from %s\n", aUrl)
	r, err := http.Get(aUrl)
	if err != nil {
		glog.Fatalf("Problem fetching salesforce data from URL %s\n", err)
	}
	defer r.Body.Close()
	return parseCCADB(r.Body)
}

func openAndParse(aPath string) ([]string, error) {
	fd, err := os.Open(aPath)
	if err != nil {
		return []string{}, err
	}
	defer fd.Close()
	return parseCCADB(fd)
}

func main() {
	flag.Parse()

	var mozIssuers []string
	var err error

	if *incsv == "<path>" {
		mozIssuers, err = downloadAndParse(kMozCCADBReport)
	} else {
		mozIssuers, err = openAndParse(*incsv)
	}

	if err != nil {
		glog.Fatal(err)
	}

	// TODO: Deduplicate the mozIssuers list

	if *outfile == "<stdout>" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", " ")
		if err = enc.Encode(mozIssuers); err != nil {
			glog.Fatal(err)
		}
		return
	}

	f, err := os.OpenFile(*outfile, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		glog.Fatal(err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	if err = enc.Encode(mozIssuers); err != nil {
		glog.Fatal(err)
	}
}
