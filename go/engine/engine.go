/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/golang/glog"
	"github.com/hashicorp/go-metrics"
	"github.com/mozilla/crlite/go/config"
	"github.com/mozilla/crlite/go/storage"
	"github.com/mozilla/crlite/go/telemetry"
)

func GetConfiguredStorage(ctx context.Context, ctconfig *config.CTConfig, roStorage bool) (storage.CertDatabase, storage.RemoteCache) {
	var err error
	var storageDB storage.CertDatabase

	redisTimeoutDuration, err := time.ParseDuration(*ctconfig.RedisTimeout)
	if err != nil {
		glog.Fatalf("Could not parse RedisTimeout: %v", err)
	}

	remoteCache, err := storage.NewRedisCache(*ctconfig.RedisHost, redisTimeoutDuration)
	if err != nil {
		glog.Fatalf("Unable to configure Redis cache for host %v", *ctconfig.RedisHost)
	}

	storageDB, err = storage.NewCertDatabase(remoteCache, *ctconfig.CertPath, roStorage)
	if err != nil {
		glog.Fatalf("Unable to construct cache and/or persistent storage: %v", err)
	}

	return storageDB, remoteCache
}

func PrepareTelemetry(utilName string, ctconfig *config.CTConfig) {
	metricsConf := metrics.DefaultConfig(utilName)
	metricsConf.EnableHostname = false
	metricsConf.EnableHostnameLabel = false
	metricsConf.EnableRuntimeMetrics = false
	metricsConf.EnableServiceLabel = false

	if len(*ctconfig.StatsDHost) > 0 {
		metricsSink, err := metrics.NewStatsdSink(fmt.Sprintf("%s:%d", *ctconfig.StatsDHost, *ctconfig.StatsDPort))
		if err != nil {
			glog.Fatal(err)
		}

		_, err = metrics.NewGlobal(metricsConf, metricsSink)
		if err != nil {
			glog.Fatal(err)
		}

		glog.Infof("%s is starting. Statistics are being reported to the StatsD server at %s:%d",
			utilName, *ctconfig.StatsDHost, *ctconfig.StatsDPort)

		return
	}

	infoDumpPeriod, err := time.ParseDuration(*ctconfig.StatsRefreshPeriod)
	if err != nil {
		glog.Fatalf("Could not parse StatsRefreshPeriod: %v", err)
	}

	glog.Infof("%s is starting. Local statistics will emit every: %s",
		utilName, infoDumpPeriod)

	metricsSink := metrics.NewInmemSink(infoDumpPeriod, 5*infoDumpPeriod)
	telemetry.NewMetricsDumper(metricsSink, infoDumpPeriod)

	_, err = metrics.NewGlobal(metricsConf, metricsSink)
	if err != nil {
		glog.Fatal(err)
	}
}
