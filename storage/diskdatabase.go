package storage

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/golang/glog"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/bluele/gcache"
	"github.com/google/certificate-transparency-go/x509"
)

type CacheEntry struct {
	mutex *sync.Mutex
	fd    *os.File
	known *KnownCertificates
}

func NewCacheEntry(aFileObj *os.File, aKnownPath string, aPerms os.FileMode) (*CacheEntry, error) {
	knownCerts := NewKnownCertificates(aKnownPath, aPerms)
	err := knownCerts.Load()
	if err != nil {
		glog.V(1).Infof("Creating new known certificates file for %s", aKnownPath)
	}

	return &CacheEntry{
		fd:    aFileObj,
		mutex: &sync.Mutex{},
		known: knownCerts,
	}, nil
}

func (ce *CacheEntry) Close() error {
	ce.mutex.Lock()
	defer ce.mutex.Unlock()
	if err := ce.fd.Close(); err != nil {
		return err
	}

	return ce.known.Save()
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

func NewDiskDatabase(aCacheSize int, aPath string, aPerms os.FileMode) (*DiskDatabase, error) {
	if !isDirectory(aPath) {
		return nil, fmt.Errorf("%s is not a directory. Aborting.", aPath)
	}

	fileObj, err := os.Open(aPath)
	if err != nil {
		return nil, err
	}

	cache := gcache.New(aCacheSize).ARC().
		EvictedFunc(func(key, value interface{}) {
			err := value.(*CacheEntry).Close()
			glog.V(2).Infof("CACHE[%s]: closed datafile: %s [err=%s]", aPath, key, err)
		}).
		PurgeVisitorFunc(func(key, value interface{}) {
			err := value.(*CacheEntry).Close()
			glog.V(2).Infof("CACHE[%s]: shutdown closed datafile: %s [err=%s]", aPath, key, err)
		}).
		LoaderFunc(func(key interface{}) (interface{}, error) {
			glog.V(2).Infof("CACHE[%s]: loaded datafile: %s", aPath, key)

			pemPath := key.(string)

			fd, err := os.OpenFile(pemPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, aPerms)
			if err != nil {
				return nil, err
			}

			knownPath := fmt.Sprintf("%s.known", pemPath)
			return NewCacheEntry(fd, knownPath, aPerms)
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

func (db *DiskDatabase) Store(aCert *x509.Certificate, aLogURL string) error {
	dirPath, filePath := db.getPathForID(&aCert.NotAfter, aCert.SubjectKeyId, aCert.AuthorityKeyId)
	if !isDirectory(dirPath) {
		err := os.MkdirAll(dirPath, os.ModeDir|0777)
		if err != nil {
			return err
		}
	}

	headers := make(map[string]string)
	headers["Log"] = aLogURL
	headers["Recorded-at"] = time.Now().Format(time.RFC3339)

	pemblock := pem.Block{
		Type:    "CERTIFICATE",
		Headers: headers,
		Bytes:   aCert.Raw,
	}

	// Be willing to try twice, since fdCache sometimes makes a mistake and
	// evicts an entry right as we're using it.
	var err error
	for t := 0; t < 2; t++ {
		obj, err := db.fdCache.Get(filePath)
		if err != nil {
			panic(err)
		}

		ce := obj.(*CacheEntry)

		certWasUnknown, err := ce.known.WasUnknown(aCert.SerialNumber)
		if err != nil {
			return err
		}

		if certWasUnknown {
			ce.mutex.Lock()
			err = pem.Encode(ce.fd, &pemblock)
			ce.mutex.Unlock()
		}

		if err == nil {
			break
		}
	}

	if err != nil {
		glog.Errorf("Cache eviction collision: ", err)
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
