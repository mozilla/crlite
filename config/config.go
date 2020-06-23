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
	LogUrlList          *string
	CertPath            *string
	GoogleProjectId     *string
	RedisHost           *string
	RedisTimeout        *string
	Offset              *uint64
	Limit               *uint64
	NumThreads          *int
	RunForever          *bool
	IssuerCNFilter      *string
	LogExpiredEntries   *bool
	SavePeriod          *string
	PollingDelayMean    *string
	PollingDelayStdDev  *int
	StatsRefreshPeriod  *string
	OutputRefreshPeriod *string
	Config              *string
	StackdriverMetrics  *bool
}

func confInt(p *int, section *ini.Section, key string, def int) {
	val, ok := os.LookupEnv(key)
	if ok {
		i, err := strconv.ParseInt(val, 10, 32)
		if err == nil {
			*p = int(i)
			return
		}
	}

	*p = def
	if section != nil {
		k := section.Key(key)
		if k != nil {
			v, err := k.Int()
			if err == nil {
				*p = v
			}
		}
	}
}

func confUint64(p *uint64, section *ini.Section, key string, def uint64) {
	// Final override is the environment variable
	val, ok := os.LookupEnv(key)
	if ok {
		u, err := strconv.ParseUint(val, 10, 64)
		if err == nil {
			*p = u
			return
		}
	}

	// Assume default
	*p = def
	if section != nil {
		k := section.Key(key)
		if k != nil {
			v, err := k.Uint64()
			if err == nil {
				*p = v
			}
		}
	}
}

func confBool(p *bool, section *ini.Section, key string, def bool) {
	// Final override is the environment variable
	val, ok := os.LookupEnv(key)
	if ok {
		b, err := strconv.ParseBool(val)
		if err == nil {
			*p = b
			return
		}
	}

	*p = def
	if section != nil {
		k := section.Key(key)
		if k != nil {
			v, err := k.Bool()
			if err == nil {
				*p = v
			}
		}
	}

}

func confString(p *string, section *ini.Section, key string, def string) {
	*p = def
	if section != nil {
		k := section.Key(key)
		if k != nil && len(k.String()) > 0 {
			*p = k.String()
		}
	}
	val, ok := os.LookupEnv(key)
	if ok {
		*p = val
	}
}

func NewCTConfig() *CTConfig {
	return &CTConfig{
		Offset:              new(uint64),
		Limit:               new(uint64),
		LogUrlList:          new(string),
		NumThreads:          new(int),
		LogExpiredEntries:   new(bool),
		RunForever:          new(bool),
		IssuerCNFilter:      new(string),
		CertPath:            new(string),
		GoogleProjectId:     new(string),
		StackdriverMetrics:  new(bool),
		RedisHost:           new(string),
		RedisTimeout:        new(string),
		SavePeriod:          new(string),
		OutputRefreshPeriod: new(string),
		StatsRefreshPeriod:  new(string),
		PollingDelayMean:    new(string),
		PollingDelayStdDev:  new(int),
	}
}

func (c *CTConfig) Init() {
	var confFile string
	var flagOffset uint64
	var flagLimit uint64
	var flagOutputRefreshPeriod string
	flag.StringVar(&confFile, "config", "", "configuration .ini file")
	flag.Uint64Var(&flagOffset, "offset", 0, "offset from the beginning")
	flag.Uint64Var(&flagLimit, "limit", 0, "limit processing to this many entries")
	flag.StringVar(&flagOutputRefreshPeriod, "outputRefreshPeriod", "125ms", "Speed for refreshing progress")

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
	confUint64(c.Offset, section, "offset", 0)
	confUint64(c.Limit, section, "limit", 0)
	confString(c.LogUrlList, section, "logList", "")
	confInt(c.NumThreads, section, "numThreads", 1)
	confBool(c.LogExpiredEntries, section, "logExpiredEntries", false)
	confBool(c.RunForever, section, "runForever", false)
	confInt(c.PollingDelayStdDev, section, "pollingDelayStdDev", 10)
	confString(c.PollingDelayMean, section, "pollingDelayMean", "10m")
	confString(c.SavePeriod, section, "savePeriod", "15m")
	confString(c.IssuerCNFilter, section, "issuerCNFilter", "")
	confString(c.CertPath, section, "certPath", "")
	confString(c.GoogleProjectId, section, "googleProjectId", "")
	confString(c.RedisHost, section, "redisHost", "")
	confString(c.RedisTimeout, section, "redisTimeout", "5s")
	confString(c.OutputRefreshPeriod, section, "outputRefreshPeriod", "125ms")
	confString(c.StatsRefreshPeriod, section, "statsRefreshPeriod", "10m")
	confBool(c.StackdriverMetrics, section, "stackdriverMetrics", false)

	// Finally, CLI flags override
	if flagOffset > 0 {
		*c.Offset = flagOffset
	}
	if flagLimit > 0 {
		*c.Limit = flagLimit
	}
	if flagOutputRefreshPeriod != "125ms" {
		*c.OutputRefreshPeriod = flagOutputRefreshPeriod
	}
}

func (c *CTConfig) Usage() {
	flag.Usage()

	fmt.Println("")
	fmt.Println("Environment variable or config file directives:")
	fmt.Println("")
	fmt.Println("Choose at most one backing store:")
	fmt.Println("certPath = Path under which to store full DER-encoded certificates")
	fmt.Println("")
	fmt.Println("The external data cache is mandatory:")
	fmt.Println("redisHost = address:port of the Redis instance")
	fmt.Println("")
	fmt.Println("Options:")
	fmt.Println("googleProjectId = Google Cloud Platform Project ID, used for stackdriver logging")
	fmt.Println("issuerCNFilter = Prefixes to match for CNs for permitted issuers, comma delimited")
	fmt.Println("runForever = Run forever, pausing `pollingDelay` between runs")
	fmt.Println("pollingDelayMean = Wait a mean of this long between polls")
	fmt.Println("pollingDelayStdDev = Use this standard deviation between polls")
	fmt.Println("logExpiredEntries = Add expired entries to the database")
	fmt.Println("numThreads = Use this many threads for normal operations")
	fmt.Println("savePeriod = Duration between state saves, e.g. 15m")
	fmt.Println("logList = URLs of the CT Logs, comma delimited")
	fmt.Println("outputRefreshPeriod = Period between output publications")
	fmt.Println("statsRefreshPeriod = Period between stats being dumped to stderr")
	fmt.Println("stackdriverMetrics = true if should log to StackDriver, requires googleProjectId")
	fmt.Println("redisTimeout = Timeout for operations from Redis, e.g. 10s")
}
