/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"context"
	"net/url"
	"os"
	"strings"

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

	issuerList, err := storageDB.GetIssuerAndDatesFromCache()
	if err != nil {
		glog.Fatal(err)
	}

	totalSerials := 0
	totalCRLs := 0

	for _, issuerObj := range issuerList {
		issuerMetadata := storageDB.GetIssuerMetadata(issuerObj.Issuer)

		crlList := issuerMetadata.CRLs()
		totalCRLs = totalCRLs + len(crlList)

		issuerDNList := issuerMetadata.Issuers()

		countIssuerSerials := 0

		glog.Infof("Issuer: %s (%v)", issuerObj.Issuer.ID(), issuerDNList)

		for _, expDate := range issuerObj.ExpDates {
			knownCerts := storageDB.GetKnownCertificates(expDate, issuerObj.Issuer)
			knownList := knownCerts.Known()
			countSerials := len(knownList)

			countIssuerSerials = countIssuerSerials + countSerials
			totalSerials = totalSerials + countSerials

			glog.V(1).Infof("- %s (%d serials)", expDate.ID(), countSerials)
			glog.V(2).Infof("  Serials: %v", knownList)

			if glog.V(3) {
				for _, serial := range knownList {
					glog.Infof("Certificate serial={%s} / {%s} / {%s}", serial.HexString(), serial.ID(),
						serial.BinaryString())

					pemBytes, err := backend.LoadCertificatePEM(context.TODO(), serial, expDate, issuerObj.Issuer)
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
		glog.Infof(" --> %d hours, %d serials known, %d crls known, %d issuerDNs known", len(issuerObj.ExpDates),
			countIssuerSerials, len(crlList), len(issuerDNList))
	}

	glog.Infof("overall totals: %d issuers, %d serials, %d crls", len(issuerList), totalSerials, totalCRLs)
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
