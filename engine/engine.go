/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package engine

import (
	"context"
	"os"
	"time"

	"github.com/armon/go-metrics"
	"github.com/golang/glog"
	"github.com/jcjones/ct-mapreduce/config"
	"github.com/jcjones/ct-mapreduce/storage"
	"github.com/jcjones/ct-mapreduce/telemetry"
)

func GetConfiguredStorage(ctx context.Context, ctconfig *config.CTConfig) (storage.CertDatabase, storage.RemoteCache, storage.StorageBackend) {
	var err error
	var storageDB storage.CertDatabase
	var backend storage.StorageBackend

	hasLocalDiskConfig := ctconfig.CertPath != nil && len(*ctconfig.CertPath) > 0
	hasGoogleConfig := ctconfig.GoogleProjectId != nil && len(*ctconfig.GoogleProjectId) > 0

	if hasLocalDiskConfig && hasGoogleConfig {
		glog.Fatal("Local Disk and Google configurations both found. Exiting.")
	}

	remoteCache, err := storage.NewRedisCache(*ctconfig.RedisHost)
	if err != nil {
		glog.Fatalf("Unable to configure Redis cache for host %v", *ctconfig.RedisHost)
	}

	if hasLocalDiskConfig {
		glog.Fatalf("Local Disk Backend currently disabled")
	}

	if hasGoogleConfig {
		backend, err = storage.NewFirestoreBackend(ctx, *ctconfig.GoogleProjectId)
		if err != nil {
			glog.Fatalf("Unable to configure Firestore for %s: %v", *ctconfig.GoogleProjectId, err)
		}

		storageDB, err = storage.NewFilesystemDatabase(backend, remoteCache)
		if err != nil {
			glog.Fatalf("Unable to construct Firestore DB for %s: %v", *ctconfig.GoogleProjectId, err)
		}
	}

	if storageDB == nil {
		ctconfig.Usage()
		os.Exit(2)
	}

	return storageDB, remoteCache, backend
}

func PrepareTelemetry(utilName string, ctconfig *config.CTConfig) {
	infoDumpPeriod, err := time.ParseDuration(*ctconfig.StatsRefreshPeriod)
	if err != nil {
		glog.Fatalf("Could not parse StatsRefreshPeriod: %v", err)
	}

	glog.Infof("%s is starting. Statistics will emit every: %s",
		utilName, infoDumpPeriod)

	metricsSink := metrics.NewInmemSink(infoDumpPeriod, 5*infoDumpPeriod)
	telemetry.NewMetricsDumper(metricsSink, infoDumpPeriod)
	_, err = metrics.NewGlobal(metrics.DefaultConfig(utilName), metricsSink)
	if err != nil {
		glog.Fatal(err)
	}
}
