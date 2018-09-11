package storage

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
  "sync"
	"os"
	"path/filepath"
	"time"

	"github.com/bluele/gcache"
	"github.com/google/certificate-transparency-go/x509"
)

type CacheEntry struct {
	mutex *sync.Mutex
	fd 		*os.File
}

func (ce *CacheEntry) Close() {
	ce.mutex.Lock()
	ce.fd.Close()
	ce.mutex.Unlock()
}

type DiskDatabase struct {
	rootDir     *os.File
	permissions os.FileMode
	fdCache     gcache.Cache
}

func isDirectory(aPath string) bool {
	fileStat, err := os.Stat(aPath)
	if err != nil {
		return false
	}

	return fileStat.IsDir()
}

func NewDiskDatabase(aPath string, aPerms os.FileMode) (*DiskDatabase, error) {
	if !isDirectory(aPath) {
		return nil, fmt.Errorf("%s is not a directory. Aborting.", aPath)
	}

	// set env var VERBOSE to get cache details
	_, verbose := os.LookupEnv("VERBOSE")

	fileObj, err := os.Open(aPath)
	if err != nil {
		return nil, err
	}

	cache := gcache.New(64).ARC().
		EvictedFunc(func(key, value interface{}) {
			value.(*CacheEntry).Close()
			if verbose {
				log.Printf("CACHE[%s]: closed datafile: %s", aPath, key)
			}
		}).
		PurgeVisitorFunc(func(key, value interface{}) {
			value.(*CacheEntry).Close()
			if verbose {
				log.Printf("CACHE[%s]: shutdown closed datafile: %s", aPath, key)
			}
		}).
		LoaderFunc(func(key interface{}) (interface{}, error) {
			if verbose {
				log.Printf("CACHE[%s]: loaded datafile: %s", aPath, key)
			}

			fd, err := os.OpenFile(key.(string), os.O_APPEND|os.O_WRONLY|os.O_CREATE, aPerms)
			if err != nil {
				return nil, err
			}

			return &CacheEntry{
				fd:    fd,
				mutex: &sync.Mutex{},
			}, nil
		}).Build()

	db := &DiskDatabase{
		rootDir:     fileObj,
		permissions: aPerms,
		fdCache:     cache,
	}

	return db, nil
}

func (db *DiskDatabase) SaveLogState(aLogObj *CertificateLog) error {
	filename := base64.URLEncoding.EncodeToString([]byte(aLogObj.URL))
	dirPath := filepath.Join(db.rootDir.Name(), "state")
	filePath := filepath.Join(dirPath, filename)

	data, err := json.Marshal(aLogObj)
	if err != nil {
		return err
	}

	if !isDirectory(dirPath) {
		err := os.MkdirAll(dirPath, os.ModeDir|0777)
		if err != nil {
			return err
		}
	}

	return ioutil.WriteFile(filePath, data, 0666)
}

func (db *DiskDatabase) GetLogState(aUrl string) (*CertificateLog, error) {
	filename := base64.URLEncoding.EncodeToString([]byte(aUrl))
	filePath := filepath.Join(db.rootDir.Name(), "state", filename)

	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		// Not an error to not have a state file, just prime one for us
		return &CertificateLog{URL: aUrl}, nil
	}

	var certLogObj CertificateLog
	err = json.Unmarshal(data, &certLogObj)
	if err != nil {
		return nil, err
	}
	return &certLogObj, nil
}

func (db *DiskDatabase) getPathForID(aExpiration *time.Time, aSKI []byte, aAKI []byte) (string, string) {
	subdirName := aExpiration.Format("2006-01-02")
	dirPath := filepath.Join(db.rootDir.Name(), subdirName)

	issuerName := base64.URLEncoding.EncodeToString(aAKI)
	fileName := fmt.Sprintf("%s.pem", issuerName)
	filePath := filepath.Join(dirPath, fileName)
	return dirPath, filePath
}

func (db *DiskDatabase) markDirty(aExpiration *time.Time) error {
	subdirName := aExpiration.Format("2006-01-02")
	dirPath := filepath.Join(db.rootDir.Name(), subdirName)
	filePath := filepath.Join(dirPath, "dirty")

	_, err := os.Stat(filePath)
	if err != nil && os.IsNotExist(err) {
		return ioutil.WriteFile(filePath, []byte{}, 0666)
	}
	return nil
}

func (db *DiskDatabase) Store(aCert *x509.Certificate, aLogID int) error {
	dirPath, filePath := db.getPathForID(&aCert.NotAfter, aCert.SubjectKeyId, aCert.AuthorityKeyId)
	if !isDirectory(dirPath) {
		err := os.MkdirAll(dirPath, os.ModeDir|0777)
		if err != nil {
			return err
		}
	}

	headers := make(map[string]string)
	headers["LogID"] = fmt.Sprintf("%d", aLogID)
	headers["Recorded-at"] = time.Now().Format(time.RFC3339)

	pemblock := pem.Block{
		Type:    "CERTIFICATE",
		Headers: headers,
		Bytes:   aCert.Raw,
	}

	obj, err := db.fdCache.Get(filePath)
	if err != nil {
		panic(err)
	}

	ce := obj.(*CacheEntry)

	ce.mutex.Lock()
	defer ce.mutex.Unlock()

	err = pem.Encode(ce.fd, &pemblock)
	if err != nil {
		return err
	}

	// Mark the directory dirty
	err = db.markDirty(&aCert.NotAfter)
	if err != nil {
		return err
	}

	return nil
}

func (db *DiskDatabase) Cleanup() error {
	db.fdCache.Purge()
	return nil
}
