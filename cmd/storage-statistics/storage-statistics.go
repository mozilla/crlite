/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"context"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/jcjones/ct-mapreduce/config"
	"github.com/jcjones/ct-mapreduce/engine"
)

var (
	ctconfig = config.NewCTConfig()
)

func main() {
	ctconfig.Init()
	storageDB, _, backend := engine.GetConfiguredStorage(context.Background(), ctconfig)
	engine.PrepareTelemetry("storage-statistics", ctconfig)
	defer glog.Flush()

	expDateList, err := storageDB.ListExpirationDates(time.Now())
	if err != nil {
		glog.Fatalf("Couldn't list expiration dates: %v", err)
	}

	totalSerials := 0
	knownIssuers := make(map[string]bool)
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
			knownIssuers[issuer.ID()] = true

			knownCerts := storageDB.GetKnownCertificates(expDate, issuer)
			issuerMetadata := storageDB.GetIssuerMetadata(issuer)

			knownList := knownCerts.Known()
			crlList := issuerMetadata.CRLs()
			issuerDNList := issuerMetadata.Issuers()

			countSerials := len(knownList)
			countCRLs := len(crlList)
			countIssuerDNs := len(issuerDNList)

			dateTotalSerials = dateTotalSerials + countSerials
			dateTotalIssuers = dateTotalIssuers + 1
			dateTotalCRLs = dateTotalCRLs + countCRLs

			if countSerials == 0 {
				continue
			}

			totalSerials = totalSerials + countSerials
			totalCRLs = totalCRLs + countCRLs

			if countIssuerDNs == 0 {
				glog.Warningf("No DNs for issuer %v on %s", issuer.ID(), expDate)
			}

			glog.V(1).Infof(" * %s (%v): %d serials known, %d crls known, %d issuerDNs known", issuer.ID(), issuerDNList, countSerials, countCRLs, countIssuerDNs)
			glog.V(2).Infof("Serials: %v", knownList)

			if glog.V(3) {
				for _, serial := range knownList {
					glog.Infof("Certificate serial={%s} / {%s} / {%s}", serial.HexString(), serial.ID(), serial.Ascii85())

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

	glog.Infof("overall totals: %d issuers, %d serials, %d crls", len(knownIssuers), totalSerials, totalCRLs)
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
