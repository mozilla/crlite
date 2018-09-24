package main

import (
	"flag"
	"os"
	"path/filepath"
	"time"

	"github.com/golang/glog"
	"github.com/jcjones/ct-mapreduce/config"
	"github.com/jcjones/ct-mapreduce/storage"
)

var (
	ctconfig = config.NewCTConfig()
)

func main() {
	glog.Infof("OK, operating on:")
	for _, path := range flag.Args() {
		glog.Infof("Path: %s", path)
	}

	var err error
	var storageDB storage.CertDatabase
	if ctconfig.CertPath != nil && len(*ctconfig.CertPath) > 0 {
		glog.Infof("Loading from disk at %s", *ctconfig.CertPath)
		storageDB, err = storage.NewDiskDatabase(*ctconfig.CacheSize, *ctconfig.CertPath, 0644)
		if err != nil {
			glog.Fatalf("unable to open Certificate Path: %s: %s", ctconfig.CertPath, err)
		}
	}

	if storageDB == nil {
		ctconfig.Usage()
		os.Exit(2)
	}

	expDates, err := storageDB.ListExpirationDates(time.Now())
	if err != nil {
		glog.Fatalf("Could not list expiration dates", err)
	}

	for _, expDate := range expDates {
		issuers, err := storageDB.ListIssuersForExpirationDate(expDate)
		if err != nil {
			glog.Fatalf("Could not list issuers (%s) %s", expDate, err)
		}
		glog.Infof("Processing expiration date %s: (%d issuers)", expDate, len(issuers))

		for _, issuer := range issuers {
			glog.Infof("Processing %s", filepath.Join(*ctconfig.CertPath, expDate, issuer))
			err = storageDB.ReconstructIssuerMetadata(expDate, issuer)
			if err != nil {
				glog.Fatalf("Error reconstructing issuer metadata (%s / %s) %s", expDate, issuer, err)
			}
		}
	}

}
