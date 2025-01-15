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
	permModeDir = 0755
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
	cache          RemoteCache
	cacheAccessors gcache.Cache
	storageDir     string
}

func NewCertDatabase(aCache RemoteCache, aStorageDir string) (CertDatabase, error) {
	db := CertDatabase{
		cache:          aCache,
		cacheAccessors: gcache.New(8 * 1024).ARC().Build(),
		storageDir:     aStorageDir,
	}

	err := os.MkdirAll(db.serialsDir(), permModeDir)
	if err != nil {
		return db, err
	}

	return db, nil
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

func (db *CertDatabase) Store(aCert *x509.Certificate, aIssuer *x509.Certificate,
	aLogURL string, aEntryId int64) error {
	expDate := types.NewExpDateFromTime(aCert.NotAfter)
	issuer := types.NewIssuer(aIssuer)
	serialWriter := db.GetSerialCacheAccessor(expDate, issuer)

	serial := types.NewSerial(aCert)

	_, err := serialWriter.Insert(serial)
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

func (db *CertDatabase) GetSerialCacheAccessor(aExpDate types.ExpDate, aIssuer types.Issuer) *SerialCacheWriter {
	var kc *SerialCacheWriter

	id := aIssuer.ID() + aExpDate.ID()

	cacheObj, err := db.cacheAccessors.GetIFPresent(id)
	if err != nil {
		if err == gcache.KeyNotFoundError {
			kc = NewSerialCacheWriter(aExpDate, aIssuer, db.cache)
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
		kc = cacheObj.(*SerialCacheWriter)
	}

	if kc == nil {
		panic("kc is null")
	}
	return kc
}

func (db *CertDatabase) ReadSerialsFromCache(aExpDate types.ExpDate, aIssuer types.Issuer) []types.Serial {
	accessor := db.GetSerialCacheAccessor(aExpDate, aIssuer)
	return accessor.List()
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
	cacheWriter := db.GetSerialCacheAccessor(aExpDate, aIssuer)
	err = cacheWriter.RemoveMany(cachedSerials)
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
		// We'll process the expiry shards in parallel. There are only a
		// few thousand shards per issuer, and goroutines are cheap, so
		// we don't need to worry about spinning up too many workers.
		glog.Infof("[%s] Moving %d expiry bins to storage.", issuer.ID(), len(issuerDate.ExpDates))
		errChan := make(chan error, len(issuerDate.ExpDates))
		var wg sync.WaitGroup
		wg.Add(len(issuerDate.ExpDates))
		for _, expDate := range issuerDate.ExpDates {
			go func(expDate types.ExpDate) {
				errChan <- db.moveOneBinOfCachedSerialsToStorage(tmpDir, expDate, issuer)
				wg.Done()
			}(expDate)
		}
		wg.Wait()
		close(errChan)
		for err := range errChan {
			if err != nil {
				return err
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
