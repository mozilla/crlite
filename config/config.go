/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package config

import (
	"flag"
	"fmt"
	"os"
	"os/user"
	"strconv"

	"github.com/golang/glog"
	"gopkg.in/ini.v1"
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

func confInt(p *int, section *ini.Section, key string, def int) {
	*p = def
	if section != nil {
		k := section.Key(key)
		if k != nil {
			v, err := k.Int()
			if err != nil {
				*p = v
			}
		}
	}
	val, ok := os.LookupEnv(key)
	if ok {
		i, err := strconv.ParseInt(val, 10, 32)
		if err == nil {
			*p = int(i)
		}
	}
}

func confUint64(p *uint64, section *ini.Section, key string, def uint64) {
	*p = def
	if section != nil {
		k := section.Key(key)
		if k != nil {
			v, err := k.Uint64()
			if err != nil {
				*p = v
			}
		}
	}
	val, ok := os.LookupEnv(key)
	if ok {
		u, err := strconv.ParseUint(val, 10, 64)
		if err == nil {
			*p = u
		}
	}
}

func confBool(p *bool, section *ini.Section, key string, def bool) {
	*p = def
	if section != nil {
		k := section.Key(key)
		if k != nil {
			v, err := k.Bool()
			if err != nil {
				*p = v
			}
		}
	}
	val, ok := os.LookupEnv(key)
	if ok {
		b, err := strconv.ParseBool(val)
		if err == nil {
			*p = b
		}
	}
}

func confString(p *string, section *ini.Section, key string, def string) {
	*p = def
	if section != nil {
		k := section.Key(key)
		if k != nil {
			*p = k.String()
		}
	}
	val, ok := os.LookupEnv(key)
	if ok {
		*p = val
	}
}

func NewCTConfig() *CTConfig {
	var confFile string
	var flagOffset uint64
	var flagLimit uint64
	var flagOutputRefreshMs uint64
	flag.StringVar(&confFile, "config", "", "configuration .ini file")
	flag.Uint64Var(&flagOffset, "offset", 0, "offset from the beginning")
	flag.Uint64Var(&flagLimit, "limit", 0, "limit processing to this many entries")
	flag.Uint64Var(&flagOutputRefreshMs, "outputRefreshMs", 125, "Speed for refreshing progress")

	flag.Parse()

	if len(confFile) == 0 {
		userObj, err := user.Current()
		if err == nil {
			defPath := fmt.Sprintf("%s/.ct-fetch.ini", userObj.HomeDir)
			if _, err := os.Stat(defPath); err == nil {
				confFile = defPath
			}
		}
	}

	ret := CTConfig{
		Offset:             new(uint64),
		Limit:              new(uint64),
		LogUrlList:         new(string),
		NumThreads:         new(int),
		CacheSize:          new(int),
		LogExpiredEntries:  new(bool),
		RunForever:         new(bool),
		PollingDelay:       new(int),
		IssuerCNFilter:     new(string),
		CertPath:           new(string),
		FirestoreProjectId: new(string),
		OutputRefreshMs:    new(uint64),
	}

	// First, check the config file, which might have come from a CLI paramater
	var section *ini.Section
	if len(confFile) > 0 {
		cfg, err := ini.Load(confFile)
		if err == nil {
			glog.Infof("Loaded config file from %s\n", confFile)
			section = cfg.Section("")
		} else {
			glog.Errorf("Could not load config file: %s\n", err)
		}
	}

	// Fill in values, where conf file < env vars
	confUint64(ret.Offset, section, "offset", 0)
	confUint64(ret.Limit, section, "limit", 0)
	confString(ret.LogUrlList, section, "logList", "")
	confInt(ret.NumThreads, section, "numThreads", 1)
	confInt(ret.CacheSize, section, "cacheSize", 64)
	confBool(ret.LogExpiredEntries, section, "logExpiredEntries", false)
	confBool(ret.RunForever, section, "runForever", false)
	confInt(ret.PollingDelay, section, "pollingDelay", 10)
	confString(ret.IssuerCNFilter, section, "issuerCNFilter", "")
	confString(ret.CertPath, section, "certPath", "")
	confString(ret.FirestoreProjectId, section, "firestoreProjectId", "")
	confUint64(ret.OutputRefreshMs, section, "outputRefreshMs", 125)

	// Finally, CLI flags override
	if flagOffset > 0 {
		*ret.Offset = flagOffset
	}
	if flagLimit > 0 {
		*ret.Limit = flagLimit
	}
	if flagOutputRefreshMs != 125 {
		*ret.OutputRefreshMs = flagOutputRefreshMs
	}

	return &ret
}

func (c *CTConfig) Usage() {
	flag.Usage()

	fmt.Println("")
	fmt.Println("Environment variable or config file directives:")
	fmt.Println("")
	fmt.Println("Choose one backing store:")
	fmt.Println("certPath = Path under which to store full DER-encoded certificates")
	fmt.Println("firestoreProjectId = Google Cloud Platform Project ID")
	fmt.Println("")
	fmt.Println("issuerCNFilter = Prefixes to match for CNs for permitted issuers, comma delimited")
	fmt.Println("runForever = Run forever, pausing `pollingDelay` between runs")
	fmt.Println("pollingDelay = Wait this many minutes between polls")
	fmt.Println("logExpiredEntries = Add expired entries to the database")
	fmt.Println("numThreads = Use this many threads for database insertions")
	fmt.Println("cacheSize = Cache this many issuer/date files' state at a time")
	fmt.Println("logList = URLs of the CT Logs, comma delimited")
	fmt.Println("outputRefreshMs = Milliseconds between output publications")
}
