/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package utils

import (
	"flag"
	"github.com/vharitonsky/iniflags"
)

type CTConfig struct {
	LogUrl              *string
	LogUrlList          *string
	CensysPath          *string
	CensysUrl           *string
	CensysStdin         *bool
	DbConnect           *string
	Verbose             *bool
	SQLDebug            *bool
	CertPath            *string
	CertsPerFolder      *uint64
	Offset              *uint64
	OffsetByte          *uint64
	Limit               *uint64
	GeoipDbPath         *string
	NumThreads          *int
	HistoricalDays      *int
	RunForever          *bool
	PollingDelay        *int
	IssuerCNFilter      *string
	EarliestDateFilter  *string
	CorrelateLogEntries *bool
	LogExpiredEntries   *bool
}

func NewCTConfig() *CTConfig {
	ret := &CTConfig{
		LogUrl:              flag.String("log", "", "URL of the CT Log"),
		LogUrlList:          flag.String("logList", "", "URLs of the CT Logs, comma delimited"),
		CensysPath:          flag.String("censysJson", "", "Path to a Censys.io certificate json dump"),
		CensysUrl:           flag.String("censysUrl", "", "URL to a Censys.io certificate json dump"),
		CensysStdin:         flag.Bool("censysStdin", false, "Read a Censys.io json dump from stdin"),
		DbConnect:           flag.String("dbConnect", "", "DB Connection String"),
		Verbose:             flag.Bool("v", false, "Give verbose output"),
		SQLDebug:            flag.Bool("sqldebug", false, "Give sql-debug output"),
		CertPath:            flag.String("certPath", "", "Path under which to store full DER-encoded certificates"),
		CertsPerFolder:      flag.Uint64("certsPerFolder", 16384, "Certificates per folder, when stored"),
		Offset:              flag.Uint64("offset", 0, "offset from the beginning"),
		OffsetByte:          flag.Uint64("offsetByte", 0, "byte offset from the beginning, only for censysJson and not compatible with offset"),
		Limit:               flag.Uint64("limit", 0, "limit processing to this many entries"),
		GeoipDbPath:         flag.String("geoipDbPath", "", "Path to GeoIP2-City.mmdb"),
		NumThreads:          flag.Int("numThreads", 1, "Use this many threads per CPU"),
		HistoricalDays:      flag.Int("histDays", 90, "Update this many days of historical data"),
		RunForever:          flag.Bool("forever", false, "Run forever"),
		PollingDelay:        flag.Int("pollingDelay", 10, "Wait this many minutes between polls"),
		IssuerCNFilter:      flag.String("issuerCNList", "", "Prefixes to match for CNs for permitted issuers, comma delimited"),
		EarliestDateFilter:  flag.String("earliestDate", "", "Datestamp (YYYY-MM-DD) of the earliest date to accept"),
		CorrelateLogEntries: flag.Bool("correlateLogEntries", false, "Maintain a list of what certificates were found in which logs"),
		LogExpiredEntries:   flag.Bool("logExpiredEntries", false, "Add expired entries to the database"),
	}

	iniflags.Parse()
	return ret
}

func (c *CTConfig) Usage() {
	flag.Usage()
}
