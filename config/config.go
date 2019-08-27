/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package config

import (
	"flag"
	"fmt"
	"github.com/golang/glog"
	"gopkg.in/ini.v1"
	"os/user"
)

type CTConfig struct {
	LogUrlList         *string
	CertPath           *string
	FirestoreProjectId *string
	Offset             *uint64
	Limit              *uint64
	NumThreads         *int
	CacheSize          *int
	RunForever         *bool
	PollingDelay       *int
	IssuerCNFilter     *string
	LogExpiredEntries  *bool
	OutputRefreshMs    *uint64
	Config             *string
}

func NewCTConfig() *CTConfig {
	userObj, err := user.Current()
	confFile := ".ct-fetch.ini"
	if err == nil {
		confFile = fmt.Sprintf("%s/.ct-fetch.ini", userObj.HomeDir)
	}

	ret := &CTConfig{
		Offset:             flag.Uint64("offset", 0, "offset from the beginning"),
		Limit:              flag.Uint64("limit", 0, "limit processing to this many entries"),
		Config:             flag.String("config", confFile, "configuration .ini file"),
		LogUrlList:         new(string),
		NumThreads:         new(int),
		CacheSize:          new(int),
		LogExpiredEntries:  new(bool),
		RunForever:         flag.Bool("forever", false, "poll for updates forever"),
		PollingDelay:       new(int),
		IssuerCNFilter:     new(string),
		CertPath:           new(string),
		FirestoreProjectId: new(string),
		OutputRefreshMs:    flag.Uint64("output_refresh_ms", 125, "Speed for refreshing progress"),
	}
	flag.Parse()

	cfg, err := ini.Load(*ret.Config)
	if err == nil {
		glog.Infof("Loaded config file from %s\n", *ret.Config)
		*ret.LogUrlList = cfg.Section("").Key("logList").String()
		*ret.NumThreads = cfg.Section("").Key("numThreads").MustInt(1)
		*ret.CacheSize = cfg.Section("").Key("cacheSize").MustInt(64)
		*ret.LogExpiredEntries = cfg.Section("").Key("logExpiredEntries").MustBool(false)
		*ret.RunForever = cfg.Section("").Key("runForever").MustBool(false)
		*ret.PollingDelay = cfg.Section("").Key("pollingDelay").MustInt(10)
		*ret.IssuerCNFilter = cfg.Section("").Key("issuerCNFilter").String()
		*ret.CertPath = cfg.Section("").Key("certPath").String()
		*ret.FirestoreProjectId = cfg.Section("").Key("firestoreProjectId").String()
	} else {
		glog.Errorf("Could not load config file: %s\n", err)
	}

	return ret
}

func (c *CTConfig) Usage() {
	flag.Usage()

	fmt.Println("")
	fmt.Println("Config file directives:")
	fmt.Println("")
	fmt.Println("certPath = Path under which to store full DER-encoded certificates")
	fmt.Println("firestoreProjectId = Google Cloud Platform Project ID")
	fmt.Println("issuerCNFilter = Prefixes to match for CNs for permitted issuers, comma delimited")
	fmt.Println("runForever = Run forever, pausing `pollingDelay` between runs")
	fmt.Println("pollingDelay = Wait this many minutes between polls")
	fmt.Println("logExpiredEntries = Add expired entries to the database")
	fmt.Println("numThreads = Use this many threads for database insertions")
	fmt.Println("cacheSize = Cache this many issuer/date files' state at a time")
	fmt.Println("logList = URLs of the CT Logs, comma delimited")
}
