/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"context"
	"time"

	"github.com/golang/glog"
	"github.com/jcjones/ct-mapreduce/config"

	"cloud.google.com/go/firestore"
	"google.golang.org/api/iterator"
)

var (
	ctconfig = config.NewCTConfig()
)

func main() {
	ctconfig.Init()
	ctx := context.Background()

	client, err := firestore.NewClient(ctx, *ctconfig.GoogleProjectId)
	if err != nil {
		glog.Fatalf("Couldn't construct firestore client: %s", err)
	}

	iter := client.Collection("logs").Where("type", "==", "LogState").Documents(ctx)
	for {
		docsnap, err := iter.Next()
		if err == iterator.Done {
			return
		}

		if err != nil || docsnap == nil {
			glog.Warningf("iter.Next err %v", err)
			return
		}

		offset, err := docsnap.DataAt("data")
		if err != nil {
			glog.Fatalf("Couldn't get offset for doc %v: %s", docsnap, err)
		}

		url, err := docsnap.DataAt("shortUrl")
		if err != nil {
			glog.Fatalf("Couldn't get shortUrl for doc %v: %s", docsnap, err)
		}

		timestamp, err := docsnap.DataAt("unixTime")
		if err != nil {
			glog.Fatalf("Couldn't get unixTime for doc %v: %s", docsnap, err)
		}

		date := time.Unix(timestamp.(int64), 0)

		glog.Infof("%s: position=%d lastSeenDate=%s (time=%d)", url, offset, date, timestamp)
	}
}
