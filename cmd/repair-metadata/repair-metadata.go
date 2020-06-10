/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"context"
	"fmt"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"cloud.google.com/go/firestore"
	"github.com/armon/go-metrics"
	"github.com/golang/glog"
	"github.com/jcjones/ct-mapreduce/config"
	"github.com/jcjones/ct-mapreduce/engine"
	"github.com/jcjones/ct-mapreduce/storage"
	"github.com/vbauerster/mpb/v5"
	"github.com/vbauerster/mpb/v5/decor"
	"google.golang.org/api/iterator"
)

var (
	ctconfig = config.NewCTConfig()
)

// Keep in-sync with firestorebackend.go
const (
	kFieldType    = "type"
	kFieldExpDate = "expDate"
	kFieldIssuer  = "issuer"
	kTypeExpDate  = "ExpDate"
	kTypeMetadata = "Metadata"
)

// Keep in-sync with reprocess-known-certs.go
const (
	kIssuerExpdateQueueName = "reprocess-issuerExpDateWorkQueue"
)

func getExpDateFromPath(path string) (string, error) {
	parts := strings.Split(path, "/")
	if len(parts) < 6 {
		return "", fmt.Errorf("Path too short. len=%d parts=%v", len(parts), parts)
	}
	return parts[6], nil
}

func getExpDateAndIssuerFromPath(path string) (string, string, error) {
	parts := strings.Split(path, "/")
	if len(parts) < 8 {
		return "", "", fmt.Errorf("Path too short. len=%d parts=%v", len(parts), parts)
	}
	return parts[6], parts[8], nil
}

func closeChanWhenWaitGroupCompletes(wait *sync.WaitGroup, channel chan<- string) {
	wait.Wait()
	close(channel)
}

type RepairJob struct {
	client                *firestore.Client
	extCache              storage.RemoteCache
	dateProgressBar       *mpb.Bar
	dateIssuerProgressBar *mpb.Bar
	unknownProgressBar    *mpb.Bar
}

func (rj *RepairJob) done() {
	rj.dateProgressBar.SetTotal(rj.dateProgressBar.Current(), true)
	rj.dateIssuerProgressBar.SetTotal(rj.dateIssuerProgressBar.Current(), true)
	rj.unknownProgressBar.SetTotal(rj.unknownProgressBar.Current(), true)
}

func (rj *RepairJob) processCollectionRef(ctx context.Context, q *firestore.CollectionRef,
	idChan chan<- string) (error, int) {
	var count int

	iter := q.DocumentRefs(ctx)
	for {
		select {
		case <-ctx.Done():
			glog.Infof("Quit received, count was %d", count)
			return nil, count
		default:
		}

		cycleTime := time.Now()

		ref, err := iter.Next()
		if err == iterator.Done {
			return nil, count
		}
		if err != nil {
			return err, count
		}
		if ref == nil {
			return fmt.Errorf("nil document returned"), count
		}

		idChan <- ref.Path

		metrics.MeasureSince([]string{"processCollectionRef"}, cycleTime)
		count += 1
	}
}

func (rj *RepairJob) enumerateExpDates(ctx context.Context, wg *sync.WaitGroup,
	expDateChan chan<- string) {
	defer wg.Done()
	defer close(expDateChan)
	expDateCollectionRef := rj.client.Collection("ct")
	err, count := rj.processCollectionRef(ctx, expDateCollectionRef, expDateChan)
	glog.V(1).Infof("enumerateExpDates %v processed, %d count, err=%v", expDateCollectionRef.ID, count, err)
}

func (rj *RepairJob) enumerateIssuersForExpDate(ctx context.Context, expDatePath string,
	expDateIssuerChan chan<- string) {
	expDateStr, err := getExpDateFromPath(expDatePath)
	if err != nil {
		glog.Error(err)
		return
	}

	path := filepath.Join("ct", expDateStr, "issuer")
	issuerRef := rj.client.Collection(path)
	if issuerRef == nil {
		glog.Fatalf("Got a null issuerRef for %s", path)
		return
	}

	err, count := rj.processCollectionRef(ctx, issuerRef, expDateIssuerChan)
	glog.V(1).Infof("enumerateIssuersForExpDate %v issuers processed, %d count, err=%v", issuerRef.ID, count, err)
}

func (rj *RepairJob) handleExpDateIssuerChan(ctx context.Context, wg *sync.WaitGroup,
	expDateIssuerChan <-chan string) {
	defer wg.Done()

	var count int
	for {
		select {
		case <-ctx.Done():
			glog.Infof("Quit received, count was %d", count)
			return
		case expDateIssuerPathStr, ok := <-expDateIssuerChan:
			if !ok {
				glog.Infof("expDateIssuerChan closed")
				return
			}

			err := rj.constructExpDateIssuerMetadata(ctx, expDateIssuerPathStr)
			if err != nil {
				glog.Errorf("%s err=%v", expDateIssuerPathStr, err)
			}

			count++
		}
	}
}

func (rj *RepairJob) fillIssuerChanFromExpDateChan(ctx context.Context, wg *sync.WaitGroup, expDateChan <-chan string,
	expDateIssuerChan chan<- string) {
	defer wg.Done()

	timeStarted := time.Now()

	for {
		select {
		case <-ctx.Done():
			glog.Infof("Quit received")
			return
		case expPath, ok := <-expDateChan:
			if !ok {
				glog.Infof("expDateChan closed")
				return
			}

			str, err := getExpDateFromPath(expPath)
			if err != nil {
				glog.Fatalf("Unexpected exp date %s: %s", expPath, err)
			}
			ed, err := storage.NewExpDate(str)
			if err != nil {
				glog.Fatalf("Unexpected exp date parse error %s: %s", str, err)
			}
			if ed.IsExpiredAt(timeStarted) {
				glog.V(1).Infof("Skipping expired expDate %s", str)
				metrics.IncrCounter([]string{"expired expDate"}, 1)
				continue
			}

			err = rj.constructExpDateMetadata(ctx, expPath)
			if err != nil {
				glog.Errorf("%s err=%v", expPath, err)
				continue
			}

			rj.enumerateIssuersForExpDate(ctx, expPath, expDateIssuerChan)
		}
	}
}

func (rj *RepairJob) constructExpDateMetadata(ctx context.Context, expDatePath string) error {
	rj.dateProgressBar.IncrBy(1)

	expDateStr, err := getExpDateFromPath(expDatePath)
	if err != nil {
		return err
	}

	path := filepath.Join("ct", expDateStr)
	doc := rj.client.Doc(path)
	if doc == nil {
		return fmt.Errorf("nil doc making %s", path)
	}

	_, err = doc.Set(ctx, map[string]interface{}{
		kFieldType:    kTypeExpDate,
		kFieldExpDate: expDateStr,
	})

	return err
}

func (rj *RepairJob) constructExpDateIssuerMetadata(ctx context.Context, issuerPath string) error {
	rj.dateIssuerProgressBar.IncrBy(1)

	expDateStr, issuerStr, err := getExpDateAndIssuerFromPath(issuerPath)
	if err != nil {
		return err
	}

	// Construct metadata document
	path := filepath.Join("ct", expDateStr, "issuer", issuerStr)
	doc := rj.client.Doc(path)
	if doc == nil {
		return fmt.Errorf("nil doc making %s", path)
	}

	_, err = doc.Set(ctx, map[string]interface{}{
		kFieldType:    kTypeMetadata,
		kFieldExpDate: expDateStr,
		kFieldIssuer:  issuerStr,
	})
	if err != nil {
		return err
	}

	cacheKey := fmt.Sprintf("serials::%s::%s", expDateStr, issuerStr)
	exists, err := rj.extCache.Exists(cacheKey)
	if err != nil {
		return err
	}
	if !exists {
		rj.unknownProgressBar.IncrBy(1)

		glog.V(1).Infof("Key not known in cache, queuing: %s", cacheKey)
		ed, err := storage.NewExpDate(expDateStr)
		if err != nil {
			return err
		}

		tuple := storage.IssuerAndDate{
			Issuer:  storage.NewIssuerFromString(issuerStr),
			ExpDate: ed,
		}

		_, err = rj.extCache.Queue(kIssuerExpdateQueueName, tuple.String())
		if err != nil {
			return err
		}
	}

	return nil
}

func main() {
	ctconfig.Init()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer glog.Flush()

	_, extCache, _ := engine.GetConfiguredStorage(ctx, ctconfig)

	engine.PrepareTelemetry("repair-metadata", ctconfig)

	client, err := firestore.NewClient(ctx, *ctconfig.GoogleProjectId)
	if err != nil {
		glog.Fatalf("Couldn't construct firestore client: %s", err)
	}

	var wg sync.WaitGroup

	// Exit signal, used by signals from the OS
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, os.Interrupt)
	defer signal.Stop(sigChan)

	go func() {
		<-sigChan
		glog.Infof("Signal caught, stopping threads at next opportunity.")
		cancel()
		signal.Stop(sigChan)
	}()

	// Start the display
	refreshDur, err := time.ParseDuration(*ctconfig.OutputRefreshPeriod)
	if err != nil {
		glog.Fatal(err)
	}

	glog.Infof("Progress bar refresh rate is every %s.\n", refreshDur.String())

	display := mpb.NewWithContext(ctx,
		mpb.WithRefreshRate(refreshDur),
	)

	dateProgressBar := display.AddBar(math.MaxInt64,
		mpb.AppendDecorators(
			decor.Name("Expiration Dates"),
			decor.CountersNoUnit("%d%.T", decor.WC{W: 10}), // %.T ignores the total
			decor.AverageSpeed(0, "%.1f/s", decor.WCSyncSpace),
			decor.Elapsed(decor.ET_STYLE_GO, decor.WC{W: 14}),
		),
	)

	dateIssuerProgressBar := display.AddBar(math.MaxInt64,
		mpb.AppendDecorators(
			decor.Name("Date + Issuer"),
			decor.CountersNoUnit("%d%.T", decor.WC{W: 10}), // %.T ignores the total
			decor.AverageSpeed(0, "%.1f/s", decor.WCSyncSpace),
			decor.Elapsed(decor.ET_STYLE_GO, decor.WC{W: 14}),
		),
	)

	unknownProgressBar := display.AddBar(math.MaxInt64,
		mpb.AppendDecorators(
			decor.Name("Unknown"),
			decor.CountersNoUnit("%d%.T", decor.WC{W: 10}), // %.T ignores the total
			decor.AverageSpeed(0, "%.1f/s", decor.WCSyncSpace),
			decor.Elapsed(decor.ET_STYLE_GO, decor.WC{W: 14}),
		),
	)

	rj := RepairJob{
		client:                client,
		extCache:              extCache,
		dateProgressBar:       dateProgressBar,
		dateIssuerProgressBar: dateIssuerProgressBar,
		unknownProgressBar:    unknownProgressBar,
	}

	expDateChan := make(chan string)
	expDateIssuerChan := make(chan string)

	wg.Add(1)
	go rj.enumerateExpDates(ctx, &wg, expDateChan)

	for i := 0; i < *ctconfig.NumThreads; i++ {
		wg.Add(1)
		go rj.handleExpDateIssuerChan(ctx, &wg, expDateIssuerChan)
	}

	fillerWg := sync.WaitGroup{}
	for i := 0; i < *ctconfig.NumThreads; i++ {
		fillerWg.Add(1)
		go rj.fillIssuerChanFromExpDateChan(ctx, &fillerWg, expDateChan, expDateIssuerChan)
	}
	go closeChanWhenWaitGroupCompletes(&fillerWg, expDateIssuerChan)

	wg.Wait()

	rj.done()
}
