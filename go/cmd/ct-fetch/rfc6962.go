package main

import (
	"bytes"
	"context"
	"crypto"
	"fmt"
	"math/bits"
	"math/rand"
	"sort"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/hashicorp/go-metrics"

	"github.com/mozilla/crlite/go"
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

// Operates on a single log
type LogWorker struct {
	Client    *client.LogClient
	LogMeta   *types.CTLogMetadata
	STH       *ct.SignedTreeHead
	LogState  *types.CTLogState
	LogKeyId  [32]byte
	WorkOrder LogWorkerTask
	JobSize   uint64
	MetricKey string
}

func NewLogWorker(ctx context.Context, logObj *types.CTLogState, ctLogMeta *types.CTLogMetadata) (*LogWorker, error) {
	batchSize := *ctconfig.BatchSize

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
		UserAgent: userAgent,
	})
	if err != nil {
		glog.Errorf("[%s] Unable to construct CT log client: %s", ctLogMeta.URL, err)
		return nil, err
	}

	logKeyId, err := logObj.KeyID()
	if err != nil {
		glog.Errorf("[%s] Could not parse log id: %s", ctLogMeta.URL, err)
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
		task = RetryGetSTH
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
		Client:    ctLog,
		LogState:  logObj,
		LogKeyId:  logKeyId,
		LogMeta:   ctLogMeta,
		STH:       sth,
		WorkOrder: task,
		JobSize:   batchSize,
		MetricKey: metricKey,
	}, nil
}

func (lw LogWorker) Name() string {
	return lw.LogMeta.URL
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

func (lw *LogWorker) Run(ctx context.Context, entryChan chan<- LogSyncMessage) error {
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
		// The coverage cutoff for CRLite filters is
		// `LogState.MaxTimestamp - LogState.MMD`. Normally
		// MaxTimestamp is the timestamp of an entry that we have seen
		// in the log. But if we are sleeping because there are no new
		// entries in the log, then we can set MaxTimestamp equal to
		// STH.Timestamp, because no new entries with a timestamp less
		// than `STH.Timestamp - LogState.MMD` will be added. This
		// ensures that we will eventually cover the tail of a log that
		// is no longer receiving new entries.
		if lw.LogState.MaxEntry == lw.STH.TreeSize-1 {
			err := lw.updateState(ctx, nil, lw.LogState.MinEntry, lw.STH.Timestamp, entryChan)
			if err != nil {
				glog.Errorf("[%s] Failed to update log state: %s", lw.Name(), err)
				return err
			}
		}
		lw.sleep(ctx)
		return nil
	case RetryGetSTH:
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
		err = lw.updateState(ctx, &verifier.Subtree, minTimestamp, maxTimestamp, entryChan)
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

func (lw *LogWorker) updateState(ctx context.Context, newSubtree *CtLogSubtree, minTimestamp uint64, maxTimestamp uint64, entryChan chan<- LogSyncMessage) error {
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
	case Sleep:
		if newSubtree != nil {
			return fmt.Errorf("Unexpected argument")
		}
	default:
		return fmt.Errorf("Unknown work order")
	}

	// TODO(jms): We could do some consistency checks here. E.g. if the work order is
	// Update and LogState.MaxTimestamp is >= 1 MMD ahead of LogState.MinTimestamp
	// then LogState.MinTimestamp should not change.
	lw.LogState.MinTimestamp = uint64Min(lw.LogState.MinTimestamp, minTimestamp)
	lw.LogState.MaxTimestamp = uint64Max(lw.LogState.MaxTimestamp, maxTimestamp)
	lw.LogState.LastUpdateTime = time.Now()

	var emptyBytes [32]byte
	stateCopy := *lw.LogState
	select {
	case <-ctx.Done():
		return fmt.Errorf("[%s] Cancelled", lw.Name())
	case entryChan <- LogSyncMessage{nil, nil, 0, emptyBytes, &stateCopy}:
	}

	return nil
}

func (lw *LogWorker) storeLogEntry(ctx context.Context, rawLogEntry *ct.RawLogEntry, entryChan chan<- LogSyncMessage) error {
	var cert *types.Certificate
	var err error
	precert := false
	entryTimestamp := rawLogEntry.Leaf.TimestampedEntry.Timestamp

	switch rawLogEntry.Leaf.TimestampedEntry.EntryType {
	case ct.X509LogEntryType:
		cert, err = types.ParseCertificate(rawLogEntry.Cert.Data)
	case ct.PrecertLogEntryType:
		cert, err = types.ParseCertificate(rawLogEntry.Cert.Data)
		precert = true
	}

	if cert == nil {
		return fmt.Errorf("[%s] Fatal parsing error: index: %d error: %v", lw.LogMeta.URL, rawLogEntry.Index, err)
	}
	if err != nil {
		glog.Warningf("[%s] Nonfatal parsing error: index: %d error: %s", lw.LogMeta.URL, rawLogEntry.Index, err)
	}

	// Skip expired certificates unless configured otherwise
	if cert.NotAfter().Before(time.Now()) && !*ctconfig.LogExpiredEntries {
		return nil
	}

	// Skip self-signed root certificates
	if len(rawLogEntry.Chain) < 1 {
		return nil
	}

	preIssuerOrIssuingCert, err := types.ParseCertificate(rawLogEntry.Chain[0].Data)
	if preIssuerOrIssuingCert == nil {
		return fmt.Errorf("[%s] Fatal parsing error (chain[0]): index: %d error: %v", lw.LogMeta.URL, rawLogEntry.Index, err)
	}
	if err != nil {
		glog.Warningf("[%s] Nonfatal parsing error (chain[0]): index: %d error: %s", lw.LogMeta.URL, rawLogEntry.Index, err)
	}

	// RFC 6962 allows a precertificate to be signed by "a
	// special-purpose [...] Precertificate Signing Certificate
	// [that is] certified by the (root or intermediate) CA
	// certificate that will ultimately sign the end-entity". In
	// this case, the certificate that will issue the final cert is
	// the second entry in the chain (rawLogEntry.Chain[1]).
	var issuingCert *types.Certificate
	if preIssuerOrIssuingCert.IsPreIssuer() {
		if !precert {
			glog.Warningf("[%s] X509LogEntry issuer has precertificate signing EKU: index: %d", lw.LogMeta.URL, rawLogEntry.Index)
		}

		if len(rawLogEntry.Chain) < 2 {
			// The final entry of the certificate_chain array MUST
			// correspond to a root CA accepted by the log The
			// percertificate signing certificate cannot itself be
			// a root CA accepted by the log.
			return fmt.Errorf("[%s] No issuer known for certificate precert=%v index=%d serial=%s",
				lw.LogMeta.URL, precert, rawLogEntry.Index, types.NewSerialFromCertificate(cert).String())
		}

		issuingCert, err = types.ParseCertificate(rawLogEntry.Chain[1].Data)
		if issuingCert == nil {
			return fmt.Errorf("[%s] Fatal parsing error (chain[1]): index: %d error: %v", lw.LogMeta.URL, rawLogEntry.Index, err)
		}
		if err != nil {
			glog.Warningf("[%s] Nonfatal parsing error (chain[1]): index: %d error: %s", lw.LogMeta.URL, rawLogEntry.Index, err)
		}
	} else {
		issuingCert = preIssuerOrIssuingCert
	}

	// We might block while waiting for space in entryChan.
	// If we catch a signal here the verification will fail and the subtree
	// will not get merged.
	select {
	case <-ctx.Done():
		return fmt.Errorf("[%s] Cancelled", lw.Name())
	case entryChan <- LogSyncMessage{cert, issuingCert, entryTimestamp, lw.LogKeyId, nil}:
	}

	return nil
}

func (lw *LogWorker) downloadCTRangeToChannel(ctx context.Context, verifier *CtLogSubtreeVerifier, entryChan chan<- LogSyncMessage) (uint64, uint64, error) {
	var minTimestamp uint64
	var maxTimestamp uint64

	const minBackoff = 5 * time.Second
	const maxBackoff = 10 * time.Minute
	backoffDuration := minBackoff

	index := verifier.Subtree.First
	last := verifier.Subtree.Last
	for index <= last {
		resp, err := lw.Client.GetRawEntries(ctx, int64(index), int64(last))
		if err != nil {
			if strings.Contains(err.Error(), "HTTP Status") &&
				(strings.Contains(err.Error(), "429") || strings.Contains(err.Error(), "Too Many Requests")) {
				glog.Infof("[%s] received status code 429 at index=%d, retrying in %s: %v", lw.Name(), index, backoffDuration, err)

				select {
				case <-ctx.Done():
					return minTimestamp, maxTimestamp, ctx.Err()
				case <-time.After(backoffDuration):
				}

				backoffDuration *= 2
				if backoffDuration > maxBackoff {
					backoffDuration = maxBackoff
				}
				continue
			}

			glog.Warningf("Failed to get entries: %v", err)
			return minTimestamp, maxTimestamp, err
		}

		for _, entry := range resp.Entries {
			rawLogEntry, err := ct.RawLogEntryFromLeaf(int64(index), &entry)
			if err != nil {
				glog.Warningf("Erroneous entry (TLS parsing): log=%s index=%d err=%v",
					lw.Name(), index, err)

				// This is a serious error that prevents us from ingesting a log, so
				// we ping the `ct-fetch.parse.error` metric to generate an alert and
				// also the `ct-fetch.<log key>.parse.error` metric to identify the log.
				metrics.IncrCounter([]string{"parse", "error"}, 1)
				metrics.IncrCounter([]string{lw.MetricKey, "parse", "error"}, 1)
				index++
				continue
			}

			err = lw.storeLogEntry(ctx, rawLogEntry, entryChan)
			if err != nil {
				return minTimestamp, maxTimestamp, err
			}

			// Update the metadata that we will pass to mergeSubtree.
			entryTimestamp := rawLogEntry.Leaf.TimestampedEntry.Timestamp
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
