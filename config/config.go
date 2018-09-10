/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package config

import (
	"flag"
	"fmt"
	"gopkg.in/ini.v1"
	"log"
)

type CTConfig struct {
	LogUrlList        *string
	Verbose           *bool
	CertPath          *string
	Offset            *uint64
	Limit             *uint64
	NumThreads        *int
	RunForever        *bool
	PollingDelay      *int
	IssuerCNFilter    *string
	LogExpiredEntries *bool
	AWSS3Bucket       *string
	Config            *string
}

func NewCTConfig() *CTConfig {
	ret := &CTConfig{
		Verbose:           flag.Bool("v", false, "Give verbose output"),
		Offset:            flag.Uint64("offset", 0, "offset from the beginning"),
		Limit:             flag.Uint64("limit", 0, "limit processing to this many entries"),
		AWSS3Bucket:       flag.String("awsS3Bucket", "", "AWS S3 Path"),
		Config:            flag.String("config", "~/.ct-fetch.ini", "configuration .ini file"),
		LogUrlList:        new(string),
		NumThreads:        new(int),
		LogExpiredEntries: new(bool),
		RunForever:        new(bool),
		PollingDelay:      new(int),
		IssuerCNFilter:    new(string),
		CertPath:          new(string),
	}
	flag.Parse()

	cfg, err := ini.Load(*ret.Config)
	if err == nil {
		log.Printf("Loaded config file from %s", *ret.Config)
		*ret.LogUrlList = cfg.Section("").Key("logList").String()
		*ret.NumThreads = cfg.Section("").Key("numThreads").MustInt(1)
		*ret.LogExpiredEntries = cfg.Section("").Key("logExpiredEntries").MustBool(false)
		*ret.RunForever = cfg.Section("").Key("runForever").MustBool(false)
		*ret.PollingDelay = cfg.Section("").Key("pollingDelay").MustInt(10)
		*ret.IssuerCNFilter = cfg.Section("").Key("issuerCNFilter").String()
		*ret.CertPath = cfg.Section("").Key("certPath").String()
	}

	return ret
}

func (c *CTConfig) Usage() {
	flag.Usage()

	fmt.Println("")
	fmt.Println("Config file directives:")
	fmt.Println("")
	fmt.Println("certPath = Path under which to store full DER-encoded certificates")
	fmt.Println("issuerCNFilter = Prefixes to match for CNs for permitted issuers, comma delimited")
	fmt.Println("runForever = Run forever, pausing `pollingDelay` between runs")
	fmt.Println("pollingDelay = Wait this many minutes between polls")
	fmt.Println("logExpiredEntries = Add expired entries to the database")
	fmt.Println("numThreads = Use this many threads per CPU")
	fmt.Println("logList = URLs of the CT Logs, comma delimited")
}
