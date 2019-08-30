/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/jcjones/ct-mapreduce/config"
	"github.com/jcjones/ct-mapreduce/engine"
	"github.com/jcjones/ct-mapreduce/storage"
)

var (
	ctconfig = config.NewCTConfig()
)

func main() {
	storageDB, backend := engine.GetConfiguredStorage(ctconfig)

	expDateList, err := storageDB.ListExpirationDates(time.Now())
	if err != nil {
		glog.Fatalf("Couldn't list expiration dates: %v", err)
	}

	totalSerials := 0
	totalIssuers := 0
	totalCRLs := 0

	for _, expDate := range expDateList {
		dateTotalSerials := 0
		dateTotalIssuers := 0
		dateTotalCRLs := 0

		glog.Infof("Processing expiration date %s", expDate)
		issuers, err := storageDB.ListIssuersForExpirationDate(expDate)
		if err != nil {
			glog.Errorf("Couldn't list issuers for %s: %v", expDate, err)
			continue
		}

		for _, issuer := range issuers {
			knownCerts := storage.NewKnownCertificates(expDate, issuer, backend)
			err = knownCerts.Load()
			if err != nil {
				glog.Errorf("Couldn't get known certs for %s-%s: %v", expDate, issuer.ID(), err)
				continue
			}

			issuerMetadata := storage.NewIssuerMetadata(expDate, issuer, backend)
			err = issuerMetadata.Load()
			if err != nil {
				glog.Errorf("Couldn't get issuer metadata for %s-%s: %v", expDate, issuer.ID(), err)
				continue
			}

			countSerials := len(knownCerts.Known())
			countCRLs := len(issuerMetadata.Metadata.Crls)

			dateTotalSerials = dateTotalSerials + countSerials
			dateTotalIssuers = dateTotalIssuers + 1
			dateTotalCRLs = dateTotalCRLs + countCRLs

			totalSerials = totalSerials + countSerials
			totalCRLs = totalCRLs + countCRLs
			totalIssuers = totalIssuers + 1

			glog.V(1).Infof(" * %s (%s): %d serials known, %d crls known, %d issuerDNs known", issuer.ID(), *issuerMetadata.Metadata.IssuerDNs[0], countSerials, countCRLs, len(issuerMetadata.Metadata.IssuerDNs))
			glog.V(2).Infof("Serials: %v", knownCerts.Known())

			if glog.V(3) {
				for _, serial := range knownCerts.Known() {
					glog.Infof("Certificate issuer=%s serial=%s", issuer.ID(), serial.ID())

					pemBytes, err := backend.LoadCertificatePEM(serial, expDate, issuer)
					if err != nil {
						glog.Error(err)
					}

					_, err = os.Stdout.Write(pemBytes)
					if err != nil {
						glog.Error(err)
					}
				}
			}
		}

		glog.Infof("%s totals: %d issuers, %d serials, %d crls", expDate, dateTotalIssuers, dateTotalSerials, dateTotalCRLs)
	}

	glog.Infof("overall totals: %d issuers, %d serials, %d crls", totalIssuers, totalSerials, totalCRLs)
	glog.Infof("")
	glog.Infof("Log status:")

	if ctconfig.LogUrlList != nil && len(*ctconfig.LogUrlList) > 5 {
		for _, part := range strings.Split(*ctconfig.LogUrlList, ",") {
			ctLogUrl, err := url.Parse(strings.TrimSpace(part))
			if err != nil {
				glog.Fatalf("unable to set Certificate Log: %s", err)
			}

			state, err := storageDB.GetLogState(ctLogUrl)
			if err != nil {
				glog.Fatalf("unable to GetLogState: %s %v", ctLogUrl, err)
			}
			glog.Info(state.String())
		}
	}
}
