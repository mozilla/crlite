/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package engine

import (
	"context"
	"os"

	"github.com/golang/glog"
	"github.com/jcjones/ct-mapreduce/config"
	"github.com/jcjones/ct-mapreduce/storage"
)

func GetConfiguredStorage(ctconfig *config.CTConfig) (storage.CertDatabase, storage.StorageBackend) {
	var err error
	var storageDB storage.CertDatabase
	var backend storage.StorageBackend

	hasLocalDiskConfig := ctconfig.CertPath != nil && len(*ctconfig.CertPath) > 0
	hasFirestoreConfig := ctconfig.FirestoreProjectId != nil && len(*ctconfig.FirestoreProjectId) > 0

	if hasLocalDiskConfig && hasFirestoreConfig {
		glog.Fatal("Local Disk and Firestore configurations both found. Exiting.")
	}

	if hasLocalDiskConfig {
		// backend := storage.NewLocalDiskBackend(0644, *ctconfig.CertPath)
		// glog.Infof("Saving to disk at %s", *ctconfig.CertPath)
		// storageDB, err = storage.NewFilesystemDatabase(*ctconfig.CacheSize, backend)
		// if err != nil {
		// 	glog.Fatalf("unable to open Certificate Path: %+v: %+v", ctconfig.CertPath, err)
		// }
		glog.Fatalf("Local Disk Backend currently disabled")
	}

	if hasFirestoreConfig {
		ctx := context.Background()

		backend, err = storage.NewFirestoreBackend(ctx, *ctconfig.FirestoreProjectId)
		if err != nil {
			glog.Fatalf("Unable to configure Firestore for %s: %v", *ctconfig.FirestoreProjectId, err)
		}

		storageDB, err = storage.NewFilesystemDatabase(*ctconfig.CacheSize, backend)
		if err != nil {
			glog.Fatalf("Unable to construct Firestore DB for %s: %v", *ctconfig.FirestoreProjectId, err)
		}
	}

	if storageDB == nil {
		ctconfig.Usage()
		os.Exit(2)
	}

	return storageDB, backend
}
