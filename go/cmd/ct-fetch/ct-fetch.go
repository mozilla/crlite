/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// Based on github.com/jcjones/ct-sql/

package main

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/bits"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/hashicorp/go-metrics"
	"github.com/jpillora/backoff"

	"github.com/mozilla/crlite/go"
	"github.com/mozilla/crlite/go/config"
	"github.com/mozilla/crlite/go/engine"
	"github.com/mozilla/crlite/go/storage"
)

var (
	ctconfig   = config.NewCTConfig()
	httpClient = http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConnsPerHost:   10,
			DisableKeepAlives:     false,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
)

func uint64Min(x, y uint64) uint64 {
	if x < y {
		return x
	}
	return y
}

func uint64Max(x, y uint64) uint64 {
	if x > y {
		return x
	}
	return y
}

func uint64ToTimestamp(timestamp uint64) *time.Time {
	t := time.Unix(int64(timestamp/1000), int64(timestamp%1000))
	return &t
}

type CtLogEntry struct {
	LogEntry *ct.LogEntry
	LogMeta  *types.CTLogMetadata
}

type CtLogSubtree struct {
	Root  []byte
	First uint64
	Last  uint64
}

func (r *CtLogSubtree) Size() uint64 {
	return r.Last - r.First + 1
}

func (r *CtLogSubtree) Midpoint() uint64 {
	size := r.Size()
	prevPow2 := uint64(0)
	if size > 1 {
		prevPow2 = 1 << (bits.Len64(size-1) - 1)
	}
	return r.First + prevPow2
}

func rfc6962LeafHash(leaf []byte) []byte {
	// Specified in section 2.1 of RFC 6962
	h := crypto.SHA256.New()
	h.Write([]byte{0})
	h.Write(leaf)
	return h.Sum(nil)
}

func rfc6962PairHash(left, right []byte) []byte {
	// Specified in section 2.1 of RFC 6962
	h := crypto.SHA256.New()
	h.Write([]byte{1})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

type CtLogSubtreeVerifier struct {
	Subtree     CtLogSubtree
	hashStack   [][]byte // Scratch space for computing tree hash
	numConsumed uint64   // Number of leaves hashed into hashStack
}

func (v *CtLogSubtreeVerifier) Consume(leaf []byte) {
	if v.numConsumed == 0 {
		// The hash stack might need to store a full sibling path
		v.hashStack = make([][]byte, 0, bits.Len64(v.Subtree.Size())+2)
	}
	// Push the new leaf hash, H(0 || leaf), onto the stack
	v.hashStack = append(v.hashStack, rfc6962LeafHash(leaf))
	v.numConsumed += 1

	// Now we'll iteratively pop pairs of siblings off the stack and
	// replace them by their parent hash.
	var iter int
	if v.numConsumed >= v.Subtree.Size() {
		// If we've consumed the whole subtree (or too many leaves!) then
		// we'll iterate until there's only one element on the stack.
		iter = len(v.hashStack) - 1
	} else {
		// Otherwise, there is a largest complete (i.e. power-of-two sized)
		// subtree that contains the leaf that we just consumed. We'll iterate
		// until the root of that subtree is on top of the stack.
		iter = bits.TrailingZeros64(v.numConsumed)
	}
	for iter > 0 {
		n := len(v.hashStack) - 1
		L := v.hashStack[n-1]
		R := v.hashStack[n]
		v.hashStack = v.hashStack[:n-1]
		v.hashStack = append(v.hashStack, rfc6962PairHash(L, R))
		iter -= 1
	}
}

func (v *CtLogSubtreeVerifier) CheckClaim() error {
	if len(v.Subtree.Root) != crypto.SHA256.Size() {
		return fmt.Errorf("CtLogSubtreeVerifier: Claim has the wrong length.")
	}
	if v.numConsumed != v.Subtree.Size() {
		return fmt.Errorf("CtLogSubtreeVerifier: Consumed %d leaves but needed %d.", v.numConsumed, v.Subtree.Size())
	}
	if bytes.Compare(v.Subtree.Root, v.hashStack[0]) != 0 {
		return fmt.Errorf("CtLogSubtreeVerifier: Verification failed.")
	}
	return nil
}

func consistencyProofToSubtrees(proof [][]byte, oldSize, newSize uint64) ([]CtLogSubtree, error) {
	// Annotates a consistency proof with the indices needed to check it.

	if newSize <= oldSize {
		return nil, fmt.Errorf("Empty proof")
	}

	terms := make([]CtLogSubtree, 0, bits.Len64(newSize)+2)

	// A consistency proof between |oldSize| and |newSize| is
	// "almost" an inclusion proof for index |oldSize|-1 in the tree
	// of size |newSize|. "Almost" because we can omit terms from
	// the old tree so long as we provide enough information to
	// recover the old tree head.
	//
	// We represent the current node by the the set of leaves below
	// it, so each internal node of the tree looks like:
	//         [low, high]
	//          /       \
	// [low, mid-1]  [mid, high]
	// (The value of mid is determined by the size of the [low, high]
	// interval.)
	//
	// We will traverse from the root towards the leaf at index
	// |oldSize|-1, and we will record the set of leaves that lie
	// below the sibling of each node that we visit.
	//
	cursor := CtLogSubtree{First: uint64(0), Last: uint64(newSize - 1)}
	target := uint64(oldSize - 1)

	// We walk down the tree until we reach a leaf (low == high) or
	// a node which is in the old tree (high <= target). Both conditions
	// are necessary if we are to handle the |oldSize| = 0 case.
	//
	for cursor.First != cursor.Last && cursor.Last != target {
		mid := cursor.Midpoint()
		if target < mid {
			terms = append(terms, CtLogSubtree{First: mid, Last: cursor.Last})
			cursor.Last = mid - 1
		} else {
			terms = append(terms, CtLogSubtree{First: cursor.First, Last: mid - 1})
			cursor.First = mid
		}
	}

	// The cursor is at node [low, high] and we have just recorded
	// this node's sibling. We need to record enough information to
	// recover the old tree head. If |oldSize| is a power of two,
	// then the current node is the old tree head and the caller
	// already knows its value. Otherwise we need to record the
	// current node so that the caller can recover the old tree
	// head.
	//
	if (oldSize & (oldSize - 1)) != 0 { // 0 < |oldSize| is not a power of 2
		terms = append(terms, cursor)
	}

	if len(terms) != len(proof) {
		return nil, fmt.Errorf("Expected proof of length %d and got %d.",
			len(terms), len(proof))
	}

	// Reverse the list to conform with the presentation from RFC 6962
	for i, j := 0, len(terms)-1; i < j; i, j = i+1, j-1 {
		terms[i], terms[j] = terms[j], terms[i]
	}

	for i := 0; i < len(proof); i++ {
		terms[i].Root = proof[i]
	}

	return terms, nil
}

// Coordinates all workers
type LogSyncEngine struct {
	ThreadWaitGroup     *sync.WaitGroup
	DownloaderWaitGroup *sync.WaitGroup
	database            storage.CertDatabase
	entryChan           chan CtLogEntry
	lastUpdateTime      time.Time
	lastUpdateMutex     *sync.RWMutex
}

// Operates on a single log
type LogWorker struct {
	Database  storage.CertDatabase
	Client    *client.LogClient
	LogMeta   *types.CTLogMetadata
	STH       *ct.SignedTreeHead
	LogState  *types.CTLogState
	WorkOrder LogWorkerTask
	JobSize   uint64
	MetricKey string
}

func (lw LogWorker) Name() string {
	return lw.LogMeta.URL
}

type LogWorkerTask int

const (
	Init     LogWorkerTask = iota // Initialize db with one batch of recent certs
	Backfill                      // Download old certs
	Update                        // Download new certs
	Sleep                         // Wait for an STH update
)

func NewLogSyncEngine(db storage.CertDatabase) *LogSyncEngine {
	return &LogSyncEngine{
		ThreadWaitGroup:     new(sync.WaitGroup),
		DownloaderWaitGroup: new(sync.WaitGroup),
		database:            db,
		entryChan:           make(chan CtLogEntry, 1024*16),
		lastUpdateTime:      time.Time{},
		lastUpdateMutex:     &sync.RWMutex{},
	}
}

func (ld *LogSyncEngine) StartDatabaseThreads() {
	glog.Infof("Starting %d threads...", *ctconfig.NumThreads)
	for t := 0; t < *ctconfig.NumThreads; t++ {
		go ld.insertCTWorker()
	}
}

// Blocking function, run from a thread
func (ld *LogSyncEngine) SyncLog(ctx context.Context, enrolledLogs *EnrolledLogs, logMeta types.CTLogMetadata) error {
	ld.DownloaderWaitGroup.Add(1)
	defer ld.DownloaderWaitGroup.Done()

	if err := ld.database.Migrate(&logMeta); err != nil {
		return err
	}

	for {
		if !enrolledLogs.IsEnrolled(logMeta.LogID) {
			return nil
		}

		worker, err := ld.NewLogWorker(ctx, &logMeta)
		if err != nil {
			metrics.IncrCounter([]string{"sync", "error"}, 1)
			return err
		}

		err = worker.Run(ctx, ld.entryChan)
		if err != nil {
			glog.Errorf("[%s] Could not sync log: %s", logMeta.URL, err)
			metrics.IncrCounter([]string{"sync", "error"}, 1)
			return err
		}

		// We did useful work. Register an update for the health service.
		ld.RegisterUpdate()

		if !*ctconfig.RunForever {
			return nil
		}

		select {
		case <-ctx.Done():
			glog.Infof("[%s] Downloader exiting.", logMeta.URL)
			return nil
		default:
		}
	}
}

func (ld *LogSyncEngine) RegisterUpdate() {
	metrics.IncrCounter([]string{"sync", "progress"}, 1)
	ld.lastUpdateMutex.Lock()
	defer ld.lastUpdateMutex.Unlock()
	ld.lastUpdateTime = time.Now()
}

func (ld *LogSyncEngine) ApproximateMostRecentUpdateTimestamp() time.Time {
	ld.lastUpdateMutex.RLock()
	defer ld.lastUpdateMutex.RUnlock()
	return ld.lastUpdateTime
}

func (ld *LogSyncEngine) Wait() {
	// Wait for the CT Log downloaders to finish. If we're configured
	// to run forever, then this only happens if there are no enrolled logs,
	// or if all downloaders have encountered an error, or if the main thread's
	// cancel function has been called.
	ld.DownloaderWaitGroup.Wait()

	// No more log entries will be downloaded.
	close(ld.entryChan)

	// Finish handling |ld.entryChan|
	glog.Infof("Waiting on database writes to complete: %d remaining", len(ld.entryChan))
	ld.ThreadWaitGroup.Wait()
}

func (ld *LogSyncEngine) insertCTWorker() {
	ld.ThreadWaitGroup.Add(1)
	defer ld.ThreadWaitGroup.Done()

	healthStatusPeriod, _ := time.ParseDuration("15s")
	healthStatusJitter := rand.Int63n(15 * 1000)
	healthStatusDuration := healthStatusPeriod + time.Duration(healthStatusJitter)*time.Millisecond
	glog.Infof("Thread health status period: %v + %v = %v", healthStatusPeriod, healthStatusJitter, healthStatusDuration)
	healthStatusTicker := time.NewTicker(healthStatusDuration)
	defer healthStatusTicker.Stop()

	for ep := range ld.entryChan {
		select { // Taking something off the queue is useful work.
		// So indicate server health when requested.
		case <-healthStatusTicker.C:
			ld.RegisterUpdate()
		default:
		}

		var cert *x509.Certificate
		var err error
		precert := false

		switch ep.LogEntry.Leaf.TimestampedEntry.EntryType {
		case ct.X509LogEntryType:
			cert = ep.LogEntry.X509Cert
		case ct.PrecertLogEntryType:
			cert, err = x509.ParseCertificate(ep.LogEntry.Precert.Submitted.Data)
			precert = true
		}

		if cert == nil {
			glog.Errorf("[%s] Fatal parsing error: index: %d error: %v", ep.LogMeta.URL, ep.LogEntry.Index, err)
			continue
		}
		if err != nil {
			glog.Warningf("[%s] Nonfatal parsing error: index: %d error: %s", ep.LogMeta.URL, ep.LogEntry.Index, err)
		}

		// Skip expired certificates unless configured otherwise
		if cert.NotAfter.Before(time.Now()) && !*ctconfig.LogExpiredEntries {
			continue
		}

		if len(ep.LogEntry.Chain) < 1 {
			glog.Warningf("[%s] No issuer known for certificate precert=%v index=%d serial=%s subject=%+v issuer=%+v",
				ep.LogMeta.URL, precert, ep.LogEntry.Index, types.NewSerial(cert).String(), cert.Subject, cert.Issuer)
			continue
		}

		issuingCert, err := x509.ParseCertificate(ep.LogEntry.Chain[0].Data)
		if err != nil {
			glog.Errorf("[%s] Problem decoding issuing certificate: index: %d error: %s", ep.LogMeta.URL, ep.LogEntry.Index, err)
			continue
		}

		err = ld.database.Store(cert, issuingCert, ep.LogMeta.URL, ep.LogEntry.Index)
		if err != nil {
			glog.Errorf("[%s] Problem inserting certificate: index: %d error: %s", ep.LogMeta.URL, ep.LogEntry.Index, err)
		}
	}
}

func (ld *LogSyncEngine) NewLogWorker(ctx context.Context, ctLogMeta *types.CTLogMetadata) (*LogWorker, error) {
	batchSize := *ctconfig.BatchSize

	logUrlObj, err := url.Parse(ctLogMeta.URL)
	if err != nil {
		glog.Errorf("[%s] Unable to parse CT Log URL: %s", ctLogMeta.URL, err)
		return nil, err
	}

	logObj, err := ld.database.GetLogState(logUrlObj)
	if err != nil {
		glog.Errorf("[%s] Unable to get cached CT Log state: %s", ctLogMeta.URL, err)
		return nil, err
	}

	if logObj.LogID != ctLogMeta.LogID {
		// The LogID shouldn't change, but we'll treat the input as
		// authoritative. Old versions of ct-fetch didn't store the
		// LogID in redis, so we will hit this on upgrade.
		logObj.LogID = ctLogMeta.LogID
	}

	if logObj.MMD != uint64(ctLogMeta.MMD) {
		// Likewise storing MMD is new.
		logObj.MMD = uint64(ctLogMeta.MMD)
	}

	ctLog, err := client.New(ctLogMeta.URL, &httpClient, jsonclient.Options{
		UserAgent: "ct-fetch; https://github.com/mozilla/crlite",
	})
	if err != nil {
		glog.Errorf("[%s] Unable to construct CT log client: %s", ctLogMeta.URL, err)
		return nil, err
	}

	glog.Infof("[%s] Fetching signed tree head... ", ctLogMeta.URL)
	sth, fetchErr := ctLog.GetSTH(ctx)
	if fetchErr == nil {
		glog.Infof("[%s] %d total entries as of %s", ctLogMeta.URL, sth.TreeSize,
			uint64ToTimestamp(sth.Timestamp).Format(time.ANSIC))
	}

	// Determine what the worker should do.
	var task LogWorkerTask
	if fetchErr != nil {
		// Temporary network failure?
		glog.Warningf("[%s] Unable to fetch signed tree head: %s", ctLogMeta.URL, fetchErr)
		task = Sleep
	} else if sth.TreeSize <= 3 {
		// For technical reasons, we can't verify our download
		// until there are at least 3 entries in the log. So
		// we'll wait.
		task = Sleep
	} else if logObj.LastUpdateTime.IsZero() {
		// First contact with log
		task = Init
	} else if logObj.MaxEntry+batchSize < sth.TreeSize {
		// There are many new entries to download.
		task = Update
	} else if logObj.MinEntry > 0 {
		// There are not many new entries, but there's a
		// backlog of old entries. Prioritize the backlog.
		task = Backfill
	} else if time.Since(logObj.LastUpdateTime) < 10*time.Minute {
		// There are few new entries, no old entries, and we updated
		// recently. So sleep.
		task = Sleep
	} else if logObj.MaxEntry < sth.TreeSize-1 {
		// There is at least one new entry and we haven't
		// downloaded anything recently.
		task = Update
	} else {
		// There are no new entries.
		task = Sleep
	}

	metricKey := ctLogMeta.MetricKey()
	if sth != nil {
		metrics.SetGauge([]string{metricKey, "coverage"}, float32(logObj.MaxEntry-logObj.MinEntry+1)/float32(sth.TreeSize))
	}

	return &LogWorker{
		Database:  ld.database,
		Client:    ctLog,
		LogState:  logObj,
		LogMeta:   ctLogMeta,
		STH:       sth,
		WorkOrder: task,
		JobSize:   batchSize,
		MetricKey: metricKey,
	}, nil
}

func (lw *LogWorker) sleep(ctx context.Context) {
	// Sleep for ctconfig.PollingDelay seconds (+/- 10%).
	jitteredPollingDelay := (1 + 0.1*rand.NormFloat64()) * float64(*ctconfig.PollingDelay)
	duration := time.Duration(jitteredPollingDelay) * time.Second
	glog.Infof("[%s] Stopped. Sleeping for %d seconds", lw.Name(), int(jitteredPollingDelay))
	select {
	case <-ctx.Done():
		glog.Infof("[%s] Signal caught. Exiting.", lw.Name())
	case <-time.After(duration):
	}
}

func (lw *LogWorker) Run(ctx context.Context, entryChan chan<- CtLogEntry) error {
	var firstIndex, lastIndex uint64

	switch lw.WorkOrder {
	case Init:
		if lw.STH.TreeSize < lw.JobSize {
			firstIndex = 0
		} else {
			firstIndex = lw.STH.TreeSize - lw.JobSize
		}
		lastIndex = lw.STH.TreeSize - 1
		glog.Infof("[%s] Running Init job %d %d", lw.Name(), firstIndex, lastIndex)
	case Update:
		firstIndex = lw.LogState.MaxEntry + 1
		lastIndex = lw.LogState.MaxEntry + lw.JobSize
		glog.Infof("[%s] Running Update job %d %d", lw.Name(), firstIndex, lastIndex)
	case Backfill:
		// We will make fewer get-entries requests to the CT Log if we align firstIndex
		// to a power of two while backfilling.
		// TODO(jms) document the fact that JobSize should be a power of two
		if lw.LogState.MinEntry%lw.JobSize != 0 {
			firstIndex = lw.LogState.MinEntry - (lw.LogState.MinEntry % lw.JobSize)
		} else {
			// Backfill implies MinEntry > 0, so MinEntry is a non-zero multiple of
			// JobSize.
			firstIndex = lw.LogState.MinEntry - lw.JobSize
		}
		lastIndex = lw.LogState.MinEntry - 1
		glog.Infof("[%s] Running Backfill job %d %d", lw.Name(), firstIndex, lastIndex)
	case Sleep:
		lw.sleep(ctx)
		return nil
	}

	if lastIndex > lw.STH.TreeSize-1 {
		lastIndex = lw.STH.TreeSize - 1
	}

	glog.Infof("[%s] Downloading entries %d through %d",
		lw.Name(), firstIndex, lastIndex)

	// We're going to tell users that we downloaded entries
	// |firstIndex| through |lastIndex|, and we want some assurance
	// that we've actually done this (especially if we're not getting
	// entries directly from the CT Log!). We'll ask the log for a
	// consistency proof between the trees of size |firstIndex| and
	// |lastIndex+1|. We'll then check that the entries we download
	// generate the corresponding terms of the proof. We have to handle
	// the case |firstIndex| = 0 specially.
	//
	// Note: we're essentially monitoring the log (as in section 5.3
	// of RFC 6962). However, we can't always verify the consistency
	// proofs that we request because we don't always have the
	// necessary tree heads.
	//
	// TODO(jms): Check the proof when |newSize| = |lw.STH.TreeSize|
	//
	oldSize := firstIndex
	newSize := lastIndex + 1
	if oldSize == 0 {
		// Special case: the consistency proof with |oldSize| =
		// 0 is empty. With |oldSize| = 1 (or |oldSize| = 2) it
		// doesn't include a hash that depends on entry 0 (resp.
		// 0 or 1). We ensured newSize > 3 when we assigned this
		// worker its job, so we can use oldSize = 3.
		oldSize = 3
	}
	proof, err := lw.Client.GetSTHConsistency(ctx, oldSize, newSize)
	if err != nil {
		glog.Errorf("[%s] Unable to fetch consistency proof: %s", lw.Name(), err)
		lw.sleep(ctx) // Assume this is a temporary outage and wait
		return nil
	}

	// Annotate the proof with the leaves that influence each term.
	subtrees, err := consistencyProofToSubtrees(proof, oldSize, newSize)
	if err != nil {
		glog.Errorf("[%s] Could not annotate proof: %s", lw.Name(), err)
		return err
	}

	// We want to keep a contiguous set of verified entries in the
	// database at all times. We'll queue the verifiers in the right
	// order for this to happen.
	verifiers := make([]*CtLogSubtreeVerifier, 0, len(subtrees))
	switch lw.WorkOrder {
	case Init:
		fallthrough
	case Update:
		// We're updating towards the latest STH. Download subtrees
		// in order of increasing first element.
		for _, subtree := range subtrees {
			if !(firstIndex <= subtree.First && subtree.Last <= lastIndex) {
				continue
			}
			item := CtLogSubtreeVerifier{Subtree: subtree}
			pos := sort.Search(len(verifiers),
				func(i int) bool {
					return subtree.First < verifiers[i].Subtree.First
				})
			verifiers = append(verifiers, nil)
			copy(verifiers[pos+1:], verifiers[pos:])
			verifiers[pos] = &item
		}
	case Backfill:
		// We're backfilling towards index 0. Download subtrees
		// in order of decreasing last element.
		for _, subtree := range subtrees {
			if !(firstIndex <= subtree.First && subtree.Last <= lastIndex) {
				continue
			}
			item := CtLogSubtreeVerifier{Subtree: subtree}
			pos := sort.Search(len(verifiers),
				func(i int) bool {
					return subtree.Last > verifiers[i].Subtree.Last
				})
			verifiers = append(verifiers, nil)
			copy(verifiers[pos+1:], verifiers[pos:])
			verifiers[pos] = &item
		}
	}

	// Download entries and verify checksums
Loop:
	for _, verifier := range verifiers {
		minTimestamp, maxTimestamp, err := lw.downloadCTRangeToChannel(ctx, verifier, entryChan)
		if err != nil {
			glog.Errorf("[%s] downloadCTRangeToChannel exited with an error: %s.", lw.Name(), err)
			lw.sleep(ctx) // Assume this is a temporary outage and wait
			return nil
		}
		err = verifier.CheckClaim()
		if err != nil {
			glog.Errorf("[%s] downloadCTRangeToChannel could not verify entries %d-%d: %s",
				lw.Name(), verifier.Subtree.First, verifier.Subtree.Last, err)
			return err
		}
		err = lw.saveState(&verifier.Subtree, minTimestamp, maxTimestamp)
		if err != nil {
			glog.Errorf("[%s] Failed to update log state: %s", lw.Name(), err)
			return err
		}
		select {
		case <-ctx.Done():
			break Loop
		default:
		}
	}

	glog.Infof("[%s] Verified entries %d-%d", lw.Name(), verifiers[0].Subtree.First, verifiers[len(verifiers)-1].Subtree.Last)

	return nil
}

func (lw *LogWorker) saveState(newSubtree *CtLogSubtree, minTimestamp, maxTimestamp uint64) error {
	// TODO(jms) Block until entry channel is empty and database writes are complete
	// Depends on: using a separate entry channel per log

	// Ensure that the entries in newSubtree are contiguous with the DB.
	switch lw.WorkOrder {
	case Init:
		if lw.LogState.LastUpdateTime.IsZero() {
			// New log. We need to initialize Min{Entry,Timestamp}.
			// Subsequent calls with WorkOrder=Init only update Max{Entry,Timestamp}
			lw.LogState.MinEntry = newSubtree.First
			lw.LogState.MaxEntry = newSubtree.Last
			lw.LogState.MinTimestamp = minTimestamp
			lw.LogState.MaxTimestamp = maxTimestamp
		} else if lw.LogState.MaxEntry == newSubtree.First-1 {
			lw.LogState.MaxEntry = newSubtree.Last
		} else {
			return fmt.Errorf("Missing entries")
		}
	case Update:
		if lw.LogState.MaxEntry == newSubtree.First-1 {
			lw.LogState.MaxEntry = newSubtree.Last
		} else {
			return fmt.Errorf("Missing entries")
		}
	case Backfill:
		if lw.LogState.MinEntry == newSubtree.Last+1 {
			lw.LogState.MinEntry = newSubtree.First
		} else {
			return fmt.Errorf("Missing entries")
		}
	default:
		return fmt.Errorf("Unknown work order")
	}

	// TODO(jms): We could do some sanity checks here. E.g. if the work order is
	// Update and LogState.MaxTimestamp is >= 1 MMD ahead of LogState.MinTimestamp
	// then LogState.MinTimestamp should not change.
	lw.LogState.MinTimestamp = uint64Min(lw.LogState.MinTimestamp, minTimestamp)
	lw.LogState.MaxTimestamp = uint64Max(lw.LogState.MaxTimestamp, maxTimestamp)
	lw.LogState.LastUpdateTime = time.Now()

	saveErr := lw.Database.SaveLogState(lw.LogState)
	if saveErr != nil {
		return fmt.Errorf("Database error: %s", saveErr)
	}

	glog.Infof("[%s] Saved log state: %s", lw.Name(), lw.LogState)
	return nil
}

func (lw *LogWorker) downloadCTRangeToChannel(ctx context.Context, verifier *CtLogSubtreeVerifier, entryChan chan<- CtLogEntry) (uint64, uint64, error) {
	var minTimestamp uint64
	var maxTimestamp uint64

	b := &backoff.Backoff{
		Jitter: true,
		Min:    5 * time.Second,
		Max:    10 * time.Minute,
	}

	index := verifier.Subtree.First
	last := verifier.Subtree.Last
	for index <= last {
		// TODO(jms) Add an option to get entries from disk.
		resp, err := lw.Client.GetRawEntries(ctx, int64(index), int64(last))
		if err != nil {
			if strings.Contains(err.Error(), "HTTP Status") &&
				(strings.Contains(err.Error(), "429") || strings.Contains(err.Error(), "Too Many Requests")) {
				d := b.Duration()
				glog.Infof("[%s] received status code 429 at index=%d, retrying in %s: %v", lw.Name(), index, d, err)

				time.Sleep(d)
				continue
			}

			glog.Warningf("Failed to get entries: %v", err)
			return minTimestamp, maxTimestamp, err
		}
		b.Reset()

		for _, entry := range resp.Entries {
			logEntry, err := ct.LogEntryFromLeaf(int64(index), &entry)
			if _, ok := err.(x509.NonFatalErrors); !ok && err != nil {
				glog.Warningf("Erroneous certificate: log=%s index=%d err=%v",
					lw.Name(), index, err)

				// This is a serious error that prevents us from ingesting a log, so
				// we ping the `ct-fetch.parse.error` metric to generate an alert and
				// also the `ct-fetch.<log key>.parse.error` metric to identify the log.
				metrics.IncrCounter([]string{"parse", "error"}, 1)
				metrics.IncrCounter([]string{lw.MetricKey, "parse", "error"}, 1)
				index++
				continue
			}

			// We might block while waiting for space in entryChan.
			// If we catch a signal here the verification will fail and the subtree
			// will not get merged.
			select {
			case <-ctx.Done():
				glog.Infof("[%s] Cancelled", lw.Name())
				return minTimestamp, maxTimestamp, nil
			case entryChan <- CtLogEntry{logEntry, lw.LogMeta}:
			}

			// Update the metadata that we will pass to mergeSubtree.
			entryTimestamp := logEntry.Leaf.TimestampedEntry.Timestamp
			if minTimestamp == 0 || entryTimestamp < minTimestamp {
				minTimestamp = entryTimestamp
			}
			if maxTimestamp == 0 || maxTimestamp < entryTimestamp {
				maxTimestamp = entryTimestamp
			}
			verifier.Consume(entry.LeafInput)

			index++
		}
	}

	return minTimestamp, maxTimestamp, nil
}

type EnrolledLogs struct {
	wg       *sync.WaitGroup
	mutex    *sync.RWMutex
	metadata map[string]types.CTLogMetadata
	NewChan  chan types.CTLogMetadata
}

func NewEnrolledLogs() *EnrolledLogs {
	wg := new(sync.WaitGroup)
	wg.Add(1)

	return &EnrolledLogs{
		wg:       wg,
		mutex:    new(sync.RWMutex),
		metadata: make(map[string]types.CTLogMetadata),
		NewChan:  make(chan types.CTLogMetadata),
	}
}

func (el *EnrolledLogs) Finalize() {
	el.wg.Done()
	close(el.NewChan)
}

func (el *EnrolledLogs) Wait() {
	el.wg.Wait()
}

func (el *EnrolledLogs) Count() int {
	el.mutex.RLock()
	defer el.mutex.RUnlock()

	return len(el.metadata)
}
func (el *EnrolledLogs) Enroll(ctLog types.CTLogMetadata) {
	el.mutex.Lock()
	defer el.mutex.Unlock()

	_, prs := el.metadata[ctLog.LogID]
	if !prs {
		el.metadata[ctLog.LogID] = ctLog
		el.NewChan <- ctLog
	}
}

func (el *EnrolledLogs) Unenroll(ctLog types.CTLogMetadata) {
	el.mutex.Lock()
	defer el.mutex.Unlock()

	delete(el.metadata, ctLog.LogID)
}

func (el *EnrolledLogs) IsEnrolled(logID string) bool {
	el.mutex.RLock()
	defer el.mutex.RUnlock()

	_, prs := el.metadata[logID]
	return prs
}

func (el *EnrolledLogs) updateFromRemoteSettingsOnce() error {
	remoteSettingsURL, err := url.Parse(*ctconfig.RemoteSettingsURL)
	if err != nil {
		return err
	}

	if remoteSettingsURL.Scheme != "https" {
		glog.Warning("Changing RemoteSettingsURL scheme to https")
		remoteSettingsURL.Scheme = "https"
	}

	ctLogConfURL, _ := remoteSettingsURL.Parse(
		"buckets/security-state/collections/ct-logs/records")

	httpRsp, err := httpClient.Get(ctLogConfURL.String())
	if err != nil {
		return err
	}

	body, err := ioutil.ReadAll(httpRsp.Body)
	httpRsp.Body.Close()
	if err != nil {
		return err
	}

	if httpRsp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP Status %q", httpRsp.Status)
	}

	// The response from the remote settings server is
	// { "data" : []CTLogMetadata }
	var ctLogJSON map[string][]types.CTLogMetadata

	if err := json.Unmarshal([]byte(body), &ctLogJSON); err != nil {
		return err
	}

	_, exists := ctLogJSON["data"]
	if !exists {
		return fmt.Errorf("Malformed response from Remote Settings %s", *ctconfig.RemoteSettingsURL)
	}

	el.mutex.Lock()
	defer el.mutex.Unlock()
	for _, ctLog := range ctLogJSON["data"] {
		_, prs := el.metadata[ctLog.LogID]
		if prs {
			if !ctLog.CRLiteEnrolled {
				delete(el.metadata, ctLog.LogID)
				glog.Infof("[%s] Unenrolled", ctLog.URL)
			} else {
				glog.Infof("[%s] Remains enrolled", ctLog.URL)
			}
		} else {
			if ctLog.CRLiteEnrolled {
				el.metadata[ctLog.LogID] = ctLog
				el.NewChan <- ctLog
				glog.Infof("[%s] Enrolled with LogID %s", ctLog.URL, ctLog.LogID)
			}
		}
	}

	return nil
}

func (el *EnrolledLogs) UpdateFromRemoteSettings(ctx context.Context) {
	defer el.Finalize()
	for {
		glog.Infof("Updating Enrolled CT log list from remote settings.")
		err := el.updateFromRemoteSettingsOnce()
		if err != nil {
			glog.Errorf("Unable to get enrolled logs from Remote Settings: %s", err)
		}
		if !*ctconfig.RunForever {
			return
		}
		glog.Infof("There are %d logs enrolled. Polling again in %d seconds.", el.Count(), *ctconfig.RemoteSettingsUpdateInterval)
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Duration(*ctconfig.RemoteSettingsUpdateInterval) * time.Second):
		}
	}
}

func main() {
	defer glog.Flush()

	ctconfig.Init()

	ctx := context.Background()
	ctx, cancelMain := context.WithCancel(ctx)

	// Try to handle SIGINT and SIGTERM gracefully
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	defer close(sigChan)
	go func() {
		sig := <-sigChan
		glog.Infof("Signal caught: %s..", sig)
		cancelMain()
		signal.Stop(sigChan) // Restore default behavior
	}()

	// Seed random for clock jitter
	rand.Seed(time.Now().UnixNano())

	storageDB, _ := engine.GetConfiguredStorage(ctx, ctconfig)
	err := storageDB.EnsureCacheIsConsistent()
	if err != nil {
		glog.Errorf("Could not recover cache: %s", err)
		os.Exit(1)
	}

	engine.PrepareTelemetry("ct-fetch", ctconfig)

	enrolledLogs := NewEnrolledLogs()

	syncEngine := NewLogSyncEngine(storageDB)

	// Start a pool of threads to parse and store log entries
	syncEngine.StartDatabaseThreads()

	// Sync with logs as they are enrolled
	go func() {
		for ctLog := range enrolledLogs.NewChan {
			glog.Infof("[%s] Starting download.", ctLog.URL)
			go syncEngine.SyncLog(ctx, enrolledLogs, ctLog)
		}
	}()

	// Enroll logs from local settings
	if *ctconfig.CTLogMetadata != "" {
		localCTLogList := new([]types.CTLogMetadata)
		if err := json.Unmarshal([]byte(*ctconfig.CTLogMetadata), localCTLogList); err != nil {
			glog.Fatalf("Unable to parse CTLogMetadata argument: %s", err)
		}

		for _, ctLog := range *localCTLogList {
			if ctLog.CRLiteEnrolled {
				enrolledLogs.Enroll(ctLog)
			}
		}
	}

	if enrolledLogs.Count() == 0 && *ctconfig.RemoteSettingsURL == "" {
		// Didn't include a mandatory action, so print usage and exit.
		if *ctconfig.CTLogMetadata != "" {
			glog.Warningf("No enrolled logs found in %s.", *ctconfig.CTLogMetadata)
		}
		ctconfig.Usage()
		os.Exit(2)
	}

	// If we're configured with a Remote Settings URL, we'll periodically look for
	// newly enrolled logs in Remote Settings. Otherwise we have all of the logs already.
	if *ctconfig.RemoteSettingsURL != "" {
		go enrolledLogs.UpdateFromRemoteSettings(ctx)
	} else {
		enrolledLogs.Finalize()
	}

	healthHandler := http.NewServeMux()
	healthHandler.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		approxUpdateTimestamp := syncEngine.ApproximateMostRecentUpdateTimestamp()

		if approxUpdateTimestamp.IsZero() {
			w.Header().Add("Retry-After", "30")
			w.WriteHeader(503)
			_, err := w.Write([]byte("error: no health updates yet, Retry-After 30 seconds"))
			if err != nil {
				glog.Warningf("Couldn't return too early health status: %+v", err)
			}
			return
		}

		duration := time.Since(approxUpdateTimestamp)
		evaluationTime := 2 * time.Duration(*ctconfig.PollingDelay) * time.Second
		if duration > evaluationTime {
			w.WriteHeader(500)
			_, err := w.Write([]byte(fmt.Sprintf("error: %v since last update, which is longer than 2 * pollingDelay", duration)))
			if err != nil {
				glog.Warningf("Couldn't return poor health status: %+v", err)
			}
			return
		}

		w.WriteHeader(200)
		_, err := w.Write([]byte(fmt.Sprintf("ok: %v since last update, which is shorter than 2 * pollingDelay", duration)))
		if err != nil {
			glog.Warningf("Couldn't return ok health status: %+v", err)
		}
	})

	healthServer := &http.Server{
		Handler: healthHandler,
		Addr:    *ctconfig.HealthAddr,
	}
	go healthServer.ListenAndServe()

	// Wait until we've finalized enrollment.
	enrolledLogs.Wait()

	// Wait until all jobs are finished.
	syncEngine.Wait()

	if err := healthServer.Shutdown(ctx); err != nil {
		glog.Infof("HTTP server shutdown error: %v", err)
	}
	glog.Flush()

	os.Exit(0)
}
