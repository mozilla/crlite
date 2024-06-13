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
	RemoteSettingsURL            *string
	CTLogMetadata                *string
	CertPath                     *string
	GoogleProjectId              *string
	RedisHost                    *string
	RedisTimeout                 *string
	BatchSize                    *uint64
	NumThreads                   *int
	RunForever                   *bool
	LogExpiredEntries            *bool
	SavePeriod                   *string
	PollingDelay                 *uint64
	StatsRefreshPeriod           *string
	Config                       *string
	StatsDHost                   *string
	StatsDPort                   *int
	HealthAddr                   *string
	RemoteSettingsUpdateInterval *uint64
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
		BatchSize:                    new(uint64),
		RemoteSettingsURL:            new(string),
		CTLogMetadata:                new(string),
		NumThreads:                   new(int),
		LogExpiredEntries:            new(bool),
		RunForever:                   new(bool),
		CertPath:                     new(string),
		GoogleProjectId:              new(string),
		StatsDHost:                   new(string),
		StatsDPort:                   new(int),
		HealthAddr:                   new(string),
		RedisHost:                    new(string),
		RedisTimeout:                 new(string),
		SavePeriod:                   new(string),
		StatsRefreshPeriod:           new(string),
		PollingDelay:                 new(uint64),
		RemoteSettingsUpdateInterval: new(uint64),
	}
}

func (c *CTConfig) Init() {
	var confFile string
	var flagBatchSize uint64
	flag.StringVar(&confFile, "config", "", "configuration .ini file")
	flag.Uint64Var(&flagBatchSize, "batchSize", 0, "limit on number of CT log entries to download per job")

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
	confUint64(c.BatchSize, section, "batchSize", 4096)
	confString(c.RemoteSettingsURL, section, "remoteSettingsURL", "")
	confString(c.CTLogMetadata, section, "ctLogMetadata", "")
	confInt(c.NumThreads, section, "numThreads", 1)
	confBool(c.LogExpiredEntries, section, "logExpiredEntries", false)
	confBool(c.RunForever, section, "runForever", false)
	confUint64(c.PollingDelay, section, "pollingDelay", 600)
	confUint64(c.RemoteSettingsUpdateInterval, section, "remoteSettingsUpdateInterval", 3600)
	confString(c.SavePeriod, section, "savePeriod", "15m")
	confString(c.CertPath, section, "certPath", "")
	confString(c.GoogleProjectId, section, "googleProjectId", "")
	confString(c.RedisHost, section, "redisHost", "")
	confString(c.RedisTimeout, section, "redisTimeout", "5s")
	confString(c.StatsRefreshPeriod, section, "statsRefreshPeriod", "10m")
	confString(c.StatsDHost, section, "statsdHost", "")
	confInt(c.StatsDPort, section, "statsdPort", 8125)
	confString(c.HealthAddr, section, "healthAddr", ":8080")

	// Finally, CLI flags override
	if flagBatchSize > 0 {
		*c.BatchSize = flagBatchSize
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
	fmt.Println("remoteSettingsURL = The base url for remote settings requests")
	fmt.Println("ctLogMetadata = A string containing a JSON array of CTLogMetadata objects, for debugging")
	fmt.Println("googleProjectId = Google Cloud Platform Project ID, used for stackdriver logging")
	fmt.Println("runForever = Run forever, pausing `pollingDelay` seconds between runs")
	fmt.Println("pollingDelay= Wait time in seconds between polls. Jitter will be added.")
	fmt.Println("logExpiredEntries = Add expired entries to the database")
	fmt.Println("numThreads = Use this many threads for normal operations")
	fmt.Println("savePeriod = Duration between state saves, e.g. 15m")
	fmt.Println("statsRefreshPeriod = Period between stats being dumped to stderr, only if statsdDhost and statsdPort are not set")
	fmt.Println("statsdHost = host for StatsD information")
	fmt.Println("statsdPort = port for StatsD information")
	fmt.Println("redisTimeout = Timeout for operations from Redis, e.g. 10s")
	fmt.Println("healthAddr = Address to host the /health information http endpoint, e.g. localhost:8080")
}
