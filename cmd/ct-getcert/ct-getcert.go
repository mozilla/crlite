package main

import (
	"context"
	"encoding/pem"
	"flag"
	"os"

	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/x509"
)

func main() {
	var index uint64
	var logURL string
	flag.StringVar(&logURL, "log", "", "log URL")
	flag.Uint64Var(&index, "index", 0, "index")
	flag.Parse()

	ctClient, err := client.New(logURL, nil, jsonclient.Options{})
	if err != nil {
		glog.Fatalf("[%s] Unable to construct CT log client: %s", logURL, err)
	}

	ctx := context.Background()

	glog.Infof("[%s] Fetching entry %d... ", logURL, index)
	resp, err := ctClient.GetRawEntries(ctx, int64(index), int64(index))
	if err != nil {
		glog.Fatal(err)
	}

	for _, entry := range resp.Entries {
		rawEntry, err := ct.RawLogEntryFromLeaf(int64(index), &entry)
		if _, ok := err.(x509.NonFatalErrors); !ok && err != nil {
			glog.Warningf("Erroneous certificate: log=%s index=%d err=%v",
				logURL, index, err)
			continue
		}

		pemblock := pem.Block{
			Type:  "CERTIFICATE",
			Bytes: rawEntry.Cert.Data,
		}

		pemBytes := pem.EncodeToMemory(&pemblock)
		_, err = os.Stdout.Write(pemBytes)
		if err != nil {
			glog.Error(err)
		}
	}
}
