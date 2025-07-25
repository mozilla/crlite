package storage

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bluele/gcache"
	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/renameio"

	"github.com/mozilla/crlite/go"
)

const (
	permModeDir           = 0755
	kMoveSerialsBatchSize = 1000
)

func serialListExpiryLine(aExpDate types.ExpDate) string {
	return fmt.Sprintf("@%016x", aExpDate.Unix())
}

func WriteSerialList(w io.Writer, aExpDate types.ExpDate, aIssuer types.Issuer, aSerials []types.Serial) error {
	writer := bufio.NewWriter(w)
	defer writer.Flush()

	// Write the expiry date for this collection of serial numbers as a unix
	// timestamp encoded as a zero-padded 16 digit hex string. The expiry
	// date is prefixed by "@" to distinguish it from a serial number.
	_, err := writer.WriteString(serialListExpiryLine(aExpDate))
	if err != nil {
		return err
	}
	err = writer.WriteByte('\n')
	if err != nil {
		return err
	}
	for _, s := range aSerials {
		_, err := writer.WriteString(s.HexString())
		if err != nil {
			return err
		}
		err = writer.WriteByte('\n')
		if err != nil {
			return err
		}
	}

	return nil
}

type CertDatabase struct {
	cache           RemoteCache
	cacheAccessors  gcache.Cache
	storageDir      string
	readOnlyStorage bool
}

func NewCertDatabase(aCache RemoteCache, aStorageDir string, aReadOnlyStorage bool) (CertDatabase, error) {
	db := CertDatabase{
		cache:           aCache,
		cacheAccessors:  gcache.New(8 * 1024).ARC().Build(),
		storageDir:      aStorageDir,
		readOnlyStorage: aReadOnlyStorage,
	}

	_, err := os.Stat(db.serialsDir())
	if os.IsNotExist(err) && !aReadOnlyStorage {
		err := os.MkdirAll(db.serialsDir(), permModeDir)
		if err != nil {
			return db, err
		}
	}

	return db, nil
}

func (db *CertDatabase) EnsureCacheIsConsistent() error {
	storageEpoch, err := db.getStorageEpoch()
	if err != nil {
		return err
	}

	cacheEpoch, err := db.cache.GetEpoch()
	if err != nil {
		return err
	}

	if cacheEpoch == storageEpoch+1 || (cacheEpoch == 0 && storageEpoch == 0) {
		return nil
	}

	// The epochs are inconsistent, so we'll reset the cached log states
	// based on what's in storage. This ensures that the ct-fetch process
	// downloads a portion of each log that is contiguous with what's
	// already in storage.
	logStates, err := db.GetCTLogsFromStorage()
	if err != nil {
		return err
	}

	return db.cache.Restore(storageEpoch+1, logStates)

}

func (db *CertDatabase) GetIssuerAndDatesFromChannel(reader <-chan string) ([]types.IssuerDate, error) {
	// The channel entries are strings of the form "serials::<date>::<issuer id>".
	// We gather these by issuer to obtain a list of the form
	//    [(issuer 1, [date 1, date 2, ...]), (issuer 2, [...]), ...].
	issuerMap := make(map[string]types.IssuerDate)
	for entry := range reader {
		parts := strings.Split(entry, "::")
		if len(parts) != 3 {
			return []types.IssuerDate{}, fmt.Errorf("Unexpected key format: %s", entry)
		}

		issuer := types.NewIssuerFromString(parts[2])
		expDate, err := types.NewExpDate(parts[1])
		if err != nil {
			glog.Warningf("Couldn't parse expiration date %s: %s", entry, err)
			continue
		}

		_, ok := issuerMap[issuer.ID()]
		if !ok {
			issuerMap[issuer.ID()] = types.IssuerDate{
				Issuer:   issuer,
				ExpDates: make([]types.ExpDate, 0),
			}
		}

		tmp := issuerMap[issuer.ID()]
		tmp.ExpDates = append(tmp.ExpDates, expDate)
		issuerMap[issuer.ID()] = tmp
	}

	issuerList := make([]types.IssuerDate, 0, len(issuerMap))
	for _, v := range issuerMap {
		issuerList = append(issuerList, v)
	}
	return issuerList, nil
}

func (db *CertDatabase) GetIssuerAndDatesFromCache() ([]types.IssuerDate, error) {
	// The cache stores sets of serial numbers in bins that are keyed by strings
	// of the form "serials::<date>::<issuer id>".
	allChan := make(chan string)
	go func() {
		err := db.cache.KeysToChan("serials::*", allChan)
		if err != nil {
			glog.Fatalf("Couldn't list from cache")
		}
	}()

	return db.GetIssuerAndDatesFromChannel(allChan)
}

func (db *CertDatabase) GetIssuerAndDatesFromStorage() ([]types.IssuerDate, error) {
	// The storage directory has the following structure:
	// storageDir
	//  ├─ serials
	//      ├─ issuer::<issuer id 1>
	//          ├─ serials::<date 1>::<issuer id 1>
	//          ├─ serials::<date 2>::<issuer id 1>
	//          ...
	//      ├─ issuer::<issuer id 2>
	//          ├─ serials::<date 1>::<issuer id 2>
	//          ├─ serials::<date 2>::<issuer id 2>
	//          ...
	//      ...
	//
	allChan := make(chan string)
	go func() {
		defer close(allChan)
		issuerDirs, err := os.ReadDir(db.serialsDir())
		if err != nil {
			glog.Fatal(err)
		}
		for _, issuerDir := range issuerDirs {
			issuerName := issuerDir.Name()
			issuerDirFull := filepath.Join(db.serialsDir(), issuerName)
			if !(issuerDir.IsDir() && strings.HasPrefix(issuerName, "issuer::")) {
				continue
			}
			serialFiles, err := os.ReadDir(issuerDirFull)
			if err != nil {
				glog.Fatal(err)
			}
			for _, file := range serialFiles {
				name := file.Name()
				if strings.HasPrefix(name, "serials::") {
					allChan <- name
				}
			}
		}
	}()

	return db.GetIssuerAndDatesFromChannel(allChan)
}

func (db *CertDatabase) removeExpiredSerialsFromStorage(t time.Time) error {
	issuerDirs, err := os.ReadDir(db.serialsDir())
	if err != nil {
		return err
	}
	for _, issuerDir := range issuerDirs {
		issuerName := issuerDir.Name()
		issuerDirFull := filepath.Join(db.serialsDir(), issuerName)
		if !(issuerDir.IsDir() && strings.HasPrefix(issuerName, "issuer::")) {
			continue
		}
		serialFiles, err := os.ReadDir(issuerDirFull)
		if err != nil {
			return err
		}
		for _, serialFile := range serialFiles {
			name := serialFile.Name()
			serialFileFull := filepath.Join(issuerDirFull, name)
			parts := strings.Split(name, "::")
			if len(parts) != 3 {
				glog.Warningf("Unexpected serial file name: %s", name)
				continue
			}
			expDate, err := types.NewExpDate(parts[1])
			if err != nil {
				glog.Warningf("Couldn't parse expiration date %s: %s", name, err)
				continue
			}
			if expDate.IsExpiredAt(t) {
				os.Remove(serialFileFull)
			}
		}
		// If the issuerDir is now empty, remove it
		serialFiles, err = os.ReadDir(issuerDirFull)
		if err != nil {
			return err
		}
		if len(serialFiles) == 0 {
			os.Remove(issuerDirFull)
			continue
		}
	}
	return nil
}

func (db *CertDatabase) Migrate(aLogData *types.CTLogMetadata) error {
	return db.cache.Migrate(aLogData)
}

func (db *CertDatabase) SaveLogState(aLogObj *types.CTLogState) error {
	return db.cache.StoreLogState(aLogObj)
}

func (db *CertDatabase) GetLogState(aUrl *url.URL) (*types.CTLogState, error) {
	shortUrl := fmt.Sprintf("%s%s", aUrl.Host, strings.TrimRight(aUrl.Path, "/"))

	log, cacheErr := db.cache.LoadLogState(shortUrl)
	if log != nil {
		return log, cacheErr
	}

	glog.Warningf("Allocating brand new log for %+v, cache err=%v", shortUrl, cacheErr)
	return &types.CTLogState{
		ShortURL: shortUrl,
	}, nil
}

func (db *CertDatabase) PrepareSetMember(aCertificate, aIssuer *x509.Certificate) SetMemberWithExpiry {
	expDate := types.NewExpDateFromTime(aCertificate.NotAfter)
	issuer := types.NewIssuer(aIssuer)
	serial := types.NewSerial(aCertificate)
	return db.GetSerialCacheKey(expDate, issuer).NewMember(serial)
}

func (db *CertDatabase) Store(items []SetMemberWithExpiry) error {
	err := db.cache.SetInsertMany(items)
	if err != nil {
		return err
	}

	return nil
}

func (db *CertDatabase) serialsDir() string {
	return filepath.Join(db.storageDir, "serials")
}

func (db *CertDatabase) issuerDir(aIssuer types.Issuer) string {
	return filepath.Join(db.serialsDir(), "issuer::"+aIssuer.ID())
}

func (db *CertDatabase) serialFile(aExpDate types.ExpDate, aIssuer types.Issuer) string {
	issuerDir := db.issuerDir(aIssuer)
	return filepath.Join(issuerDir, "serials::"+aExpDate.ID()+"::"+aIssuer.ID())
}

func (db *CertDatabase) epochFile() string {
	return filepath.Join(db.storageDir, "epoch")
}

func (db *CertDatabase) coverageFile() string {
	return filepath.Join(db.storageDir, "ct-logs.json")
}

func (db *CertDatabase) GetCTLogsFromStorage() ([]types.CTLogState, error) {
	ctLogFD, err := os.Open(db.coverageFile())
	if err != nil {
		return nil, err
	}
	defer ctLogFD.Close()

	// Decode the JSON data
	ctLogList := make([]types.CTLogState, 0)
	decoder := json.NewDecoder(ctLogFD)
	err = decoder.Decode(&ctLogList)
	if err != nil {
		return nil, err
	}

	return ctLogList, nil
}

func (db *CertDatabase) GetSerialCacheKey(aExpDate types.ExpDate, aIssuer types.Issuer) *SerialCacheKey {
	var kc *SerialCacheKey

	id := aIssuer.ID() + aExpDate.ID()

	cacheObj, err := db.cacheAccessors.GetIFPresent(id)
	if err != nil {
		if err == gcache.KeyNotFoundError {
			kc = NewSerialCacheKey(aExpDate, aIssuer)
			err = db.cacheAccessors.Set(id, kc)
			if err != nil {
				glog.Fatalf("Couldn't set into the cache expDate=%s issuer=%s from cache: %s",
					aExpDate, aIssuer.ID(), err)
			}
		} else {
			glog.Fatalf("Couldn't load expDate=%s issuer=%s from cache: %s",
				aExpDate, aIssuer.ID(), err)
		}
	} else {
		kc = cacheObj.(*SerialCacheKey)
	}

	if kc == nil {
		panic("kc is null")
	}
	return kc
}

func (db *CertDatabase) ReadSerialsFromCache(aExpDate types.ExpDate, aIssuer types.Issuer) []types.Serial {
	return db.List(db.GetSerialCacheKey(aExpDate, aIssuer))
}

func (db *CertDatabase) ReadSerialsFromStorage(aExpDate types.ExpDate, aIssuer types.Issuer) ([]types.Serial, error) {
	path := db.serialFile(aExpDate, aIssuer)
	fd, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		// No serials with this issuer and expiry
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	scanner := bufio.NewScanner(fd)

	// The first line encodes the expiry date of the serials in the file
	if scanner.Scan() {
		line := scanner.Text()
		expectedExpiryLine := serialListExpiryLine(aExpDate)
		if line != expectedExpiryLine {
			return nil, fmt.Errorf("Unexpected expiry line. Found '%s', expected '%s'", line, expectedExpiryLine)
		}
	}

	var serialList []types.Serial
	for scanner.Scan() {
		line := scanner.Text()
		serialList = append(serialList, types.NewSerialFromHex(line))
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return serialList, nil
}

func (db *CertDatabase) moveOneBinOfCachedSerialsToStorage(aTmpDir string, aExpDate types.ExpDate, aIssuer types.Issuer) error {
	cachedSerials := db.ReadSerialsFromCache(aExpDate, aIssuer)
	if len(cachedSerials) == 0 {
		return nil
	}

	storedSerials, err := db.ReadSerialsFromStorage(aExpDate, aIssuer)
	if err != nil {
		return err
	}

	// Concatenate the serial lists and remove any duplicates
	serials := append(storedSerials, cachedSerials...)
	serials = types.SerialList(serials).Dedup()

	// Write the merged serial list to a temporary file, and atomically
	// overwrite the storage file if all goes well.
	path := db.serialFile(aExpDate, aIssuer)
	t, err := renameio.TempFile(aTmpDir, path)
	if err != nil {
		return err
	}
	defer t.Cleanup()

	err = WriteSerialList(t, aExpDate, aIssuer, serials)
	if err != nil {
		return err
	}

	err = t.CloseAtomicallyReplace()
	if err != nil {
		return err
	}

	// It's now safe to remove cachedSerials from the cache.
	key := db.GetSerialCacheKey(aExpDate, aIssuer)
	err = db.RemoveMany(key, cachedSerials)
	if err != nil {
		glog.Warningf("Failed to remove serial from cache: %s", err)
	}

	return nil
}

func (db *CertDatabase) moveCachedSerialsToStorage() error {
	issuerList, err := db.GetIssuerAndDatesFromCache()
	if err != nil {
		return err
	}

	for _, issuerDate := range issuerList {
		issuer := issuerDate.Issuer
		tmpDir := renameio.TempDir(db.issuerDir(issuer))
		err = os.MkdirAll(tmpDir, permModeDir)
		if err != nil {
			return err
		}
		batchSize := kMoveSerialsBatchSize
		for start := 0; start < len(issuerDate.ExpDates); start += batchSize {
			if start+batchSize > len(issuerDate.ExpDates) {
				batchSize = len(issuerDate.ExpDates) - start
			}
			glog.Infof("[%s] Moving %d expiry bins to storage.", issuer.ID(), batchSize)
			errChan := make(chan error, batchSize)
			var wg sync.WaitGroup
			wg.Add(batchSize)
			for i := start; i < start+batchSize; i++ {
				go func(expDate types.ExpDate) {
					errChan <- db.moveOneBinOfCachedSerialsToStorage(tmpDir, expDate, issuer)
					wg.Done()
				}(issuerDate.ExpDates[i])
			}
			wg.Wait()
			close(errChan)
			for err := range errChan {
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (db *CertDatabase) moveOneBinOfAliasedSerials(aTmpDir string, aExpDate types.ExpDate, aPreIssuer types.Issuer, aIssuer types.Issuer) error {
	aliasedSerials, err := db.ReadSerialsFromStorage(aExpDate, aPreIssuer)
	if err != nil {
		return err
	}

	if len(aliasedSerials) > 0 {
		glog.Infof("[%s] Moving %d aliased serials from %s", aIssuer.ID(), len(aliasedSerials), aPreIssuer.ID())
	} else {
		return nil
	}

	storedSerials, err := db.ReadSerialsFromStorage(aExpDate, aIssuer)
	if err != nil {
		return err
	}

	// Concatenate the serial lists and remove any duplicates
	serials := append(storedSerials, aliasedSerials...)
	serials = types.SerialList(serials).Dedup()

	// Write the merged serial list to a temporary file, and atomically
	// overwrite the issuer's file if all goes well.
	path := db.serialFile(aExpDate, aIssuer)
	t, err := renameio.TempFile(aTmpDir, path)
	if err != nil {
		return err
	}
	defer t.Cleanup()

	err = WriteSerialList(t, aExpDate, aIssuer, serials)
	if err != nil {
		return err
	}

	err = t.CloseAtomicallyReplace()
	if err != nil {
		return err
	}

	return nil
}

func (db *CertDatabase) moveAliasedSerials() error {
	issuerAndDatesList, err := db.GetIssuerAndDatesFromStorage()
	if err != nil {
		return err
	}

	for _, issuerAndDates := range issuerAndDatesList {
		preissuer := issuerAndDates.Issuer
		preissuerDates := issuerAndDates.ExpDates

		aliases, err := db.cache.GetPreIssuerAliases(preissuer)
		if err != nil {
			return err
		}
		for _, issuer := range aliases {
			tmpDir := renameio.TempDir(db.issuerDir(issuer))
			err = os.MkdirAll(tmpDir, permModeDir)
			if err != nil {
				return err
			}
			for _, expDate := range preissuerDates {
				err = db.moveOneBinOfAliasedSerials(tmpDir, expDate, preissuer, issuer)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (db *CertDatabase) getStorageEpoch() (uint64, error) {
	fd, err := os.Open(db.epochFile())
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer fd.Close()
	scanner := bufio.NewScanner(fd)
	if scanner.Scan() {
		return strconv.ParseUint(scanner.Text(), 10, 64)
	}
	if err = scanner.Err(); err != nil {
		return 0, err
	}
	return 0, nil
}

func (db *CertDatabase) Commit(aProofOfLock string) error {
	// Commit() moves serials from cache to storage, removes expired serial
	// numbers from storage, and updates the coverage metadata file. This is
	// done in four steps:
	//   1) coverage metadata is retrieved from cache and written to a
	//      temporary file,
	//   2) cached serials are moved to persistent storage,
	//   3) the coverage metadata file is atomically overwritten with the
	//      temporary file from step 1,
	//   4) expired serial numbers are removed from storage.
	// This sequence of operations ensures that the coverage metadata file
	// describes a subset of the stored serials at the end of step 3. (It
	// will typically be a strict subset, as the commit process is intended
	// to run in parallel with ct-fetch).
	//
	// The caller must hold the commit lock (i.e. the caller must store a
	// random value under the key `lock::commit` in the cache and then
	// provide that value here as `aProofOfLock`).
	//
	// The epoch value in storage must be one less than the epoch value in
	// cache (unless this is the first time that Commit() has been called,
	// in which case both epochs will be equal to 0).

	if db.readOnlyStorage {
		return fmt.Errorf("Cannot commit serials to read-only storage")
	}

	hasLock, err := db.cache.HasCommitLock(aProofOfLock)
	if err != nil {
		return err
	}
	if !hasLock {
		return errors.New("Caller must hold commit lock")
	}

	storageEpoch, err := db.getStorageEpoch()
	if err != nil {
		return err
	}

	cacheEpoch, err := db.cache.GetEpoch()
	if err != nil {
		return err
	}

	if (cacheEpoch != storageEpoch+1) && !(cacheEpoch == 0 && storageEpoch == 0) {
		return errors.New("Inconsistent cache and storage epochs. Restart ct-fetch.")
	}

	logList, err := db.cache.LoadAllLogStates()
	if err != nil {
		return err
	}

	ctLogFD, err := renameio.TempFile("", db.coverageFile())
	if err != nil {
		return err
	}
	defer ctLogFD.Cleanup()

	enc := json.NewEncoder(ctLogFD)
	if err = enc.Encode(logList); err != nil {
		return err
	}

	err = db.moveCachedSerialsToStorage()
	if err != nil {
		return err
	}

	err = ctLogFD.CloseAtomicallyReplace()
	if err != nil {
		return err
	}

	err = db.removeExpiredSerialsFromStorage(time.Now())
	if err != nil {
		return err
	}

	err = db.moveAliasedSerials()
	if err != nil {
		return err
	}

	// The data on disk is in a good state and we just have to increment
	// the cache and storage epochs. We can ignore some errors here as long
	// as the end result is that the cache is one epoch ahead of storage.
	epochFD, err := renameio.TempFile("", db.epochFile())
	if err != nil {
		glog.Warningf("Failed to increment epochs: %s", err)
		return nil
	}
	defer epochFD.Cleanup()

	writer := bufio.NewWriter(epochFD)
	_, err = writer.WriteString(fmt.Sprintf("%v\n", cacheEpoch))
	if err != nil {
		glog.Warningf("Failed to increment epochs: %s", err)
		return nil
	}
	writer.Flush()

	err = db.cache.NextEpoch()
	if err != nil {
		glog.Warningf("Failed to increment epochs: %s", err)
		return nil
	}

	err = epochFD.CloseAtomicallyReplace()
	if err != nil {
		// This is the one case where we get inconsistent epochs.
		return err
	}

	return nil
}

func (db *CertDatabase) AddPreIssuerAlias(aPreIssuer types.Issuer, aIssuer types.Issuer) error {
	return db.cache.AddPreIssuerAlias(aPreIssuer, aIssuer)
}

// Returns true if this serial was unknown. Subsequent calls with the same serial
// will return false, as it will be known then.
func (db *CertDatabase) Insert(k *SerialCacheKey, aSerial types.Serial) (bool, error) {
	result, err := db.cache.SetInsert(k.ID(), aSerial.BinaryString())
	if err != nil {
		return false, err
	}

	if !k.expirySet {
		expireTime := k.expDate.ExpireTime()
		if err := db.cache.ExpireAt(k.ID(), expireTime); err != nil {
			glog.Errorf("Couldn't set expiration time %v for serials %s: %v", expireTime, k.ID(), err)
		} else {
			k.expirySet = true
		}
	}

	return result, nil
}

func (db *CertDatabase) RemoveMany(k *SerialCacheKey, aSerials []types.Serial) error {
	// Removing an element of a set may leave the set empty. Redis
	// automatically deletes empty sets, so assume that we need to reset
	// the ExpireAt time for this set on the next Insert call.
	k.expirySet = false
	serialStrings := make([]string, len(aSerials))
	for i := 0; i < len(aSerials); i++ {
		serialStrings[i] = aSerials[i].BinaryString()
	}
	return db.cache.SetRemove(k.ID(), serialStrings)
}

func (db *CertDatabase) List(k *SerialCacheKey) []types.Serial {
	// Redis' scan methods regularly provide duplicates. The duplication
	// happens at this level, pulling from SetToChan, so we make a hash-set
	// here to de-duplicate when the memory impacts are the most minimal.
	serials := make(map[string]struct{})
	var count int

	strChan := make(chan string)
	go func() {
		err := db.cache.SetToChan(k.ID(), strChan)
		if err != nil {
			glog.Fatalf("Error obtaining list of known certificates: %v", err)
		}
	}()

	for str := range strChan {
		serials[str] = struct{}{}
		count += 1
	}

	serialList := make([]types.Serial, 0, count)
	for str := range serials {
		bs, err := types.NewSerialFromBinaryString(str)
		if err != nil {
			glog.Errorf("Failed to populate serial str=[%s] %v", str, err)
			continue
		}
		serialList = append(serialList, bs)
	}

	return serialList
}
