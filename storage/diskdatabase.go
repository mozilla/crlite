package storage

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/bluele/gcache"
	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/x509"
)

const (
	kExpirationFormat        = "2006-01-02"
	kStateDirName            = "state"
	kSuffixKnownCertificates = ".known"
	kSuffixIssuerMetadata    = ".meta"
	kSuffixCertificates      = ".pem"
)

var kPemEndCert = []byte("-----END CERTIFICATE-----\n")

func GetKnownCertificates(aPath string, aExpDate string, aIssuer string, aPerms os.FileMode) *KnownCertificates {
	pemPath := fmt.Sprintf("%s%s", filepath.Join(aPath, aExpDate, aIssuer), kSuffixCertificates)
	return GetKnownCertificatesFromPath(pemPath, aPerms)
}

func GetKnownCertificatesFromPath(aPemPath string, aPerms os.FileMode) *KnownCertificates {
	knownPath := fmt.Sprintf("%s%s", aPemPath, kSuffixKnownCertificates)

	backend := &DiskBackend{aPerms}

	knownCerts := NewKnownCertificates(knownPath, backend)
	err := knownCerts.Load()
	if err != nil {
		glog.V(1).Infof("Creating new known certificates file for %s", knownPath)
	}
	return knownCerts
}

func GetIssuerMetadata(aPath string, aExpDate string, aIssuer string, aPerms os.FileMode) *IssuerMetadata {
	pemPath := fmt.Sprintf("%s%s", filepath.Join(aPath, aExpDate, aIssuer), kSuffixCertificates)
	return GetIssuerMetadataFromPath(pemPath, aPerms)
}

func GetIssuerMetadataFromPath(aPemPath string, aPerms os.FileMode) *IssuerMetadata {
	metaPath := fmt.Sprintf("%s%s", aPemPath, kSuffixIssuerMetadata)

	issuerMetadata := NewIssuerMetadata(metaPath, aPerms)
	err := issuerMetadata.Load()
	if err != nil {
		glog.V(1).Infof("Creating new issuer metadata file for %s", metaPath)
	}

	return issuerMetadata
}

type CacheEntry struct {
	mutex *sync.Mutex
	fd    *os.File
	known *KnownCertificates
	meta  *IssuerMetadata
}

func NewCacheEntry(aFileObj *os.File, aPemPath string, aPerms os.FileMode) (*CacheEntry, error) {
	knownCerts := GetKnownCertificatesFromPath(aPemPath, aPerms)
	issuerMetadata := GetIssuerMetadataFromPath(aPemPath, aPerms)

	return &CacheEntry{
		fd:    aFileObj,
		mutex: &sync.Mutex{},
		known: knownCerts,
		meta:  issuerMetadata,
	}, nil
}

func (ce *CacheEntry) Close() error {
	ce.mutex.Lock()
	defer ce.mutex.Unlock()

	errDisk := ce.fd.Close()
	errKnown := ce.known.Save()
	errMeta := ce.meta.Save()
	if errDisk != nil || errMeta != nil || errKnown != nil {
		return fmt.Errorf("Error saving data: Disk=%s Known=%s Meta=%s", errDisk, errKnown, errMeta)
	}

	return nil
}

type DiskDatabase struct {
	rootPath    string
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

			return NewCacheEntry(fd, pemPath, aPerms)
		}).Build()

	db := &DiskDatabase{
		rootPath:    aPath,
		permissions: aPerms,
		fdCache:     cache,
	}

	return db, nil
}

func (db *DiskDatabase) ListExpirationDates(aNotBefore time.Time) ([]string, error) {
	expDates := make([]string, 0)

	err := filepath.Walk(db.rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			glog.Warningf("prevent panic by handling failure accessing a path %q: %v", path, err)
			return err
		}
		if info.IsDir() {
			if info.Name() == kStateDirName {
				return filepath.SkipDir
			}

			// Note: Parses in UTC.  Comparison granularity is only to the day.
			t, err := time.Parse(kExpirationFormat, info.Name())
			aNotBefore = time.Date(aNotBefore.Year(), aNotBefore.Month(), aNotBefore.Day(), 0, 0, 0, 0, time.UTC)
			if err == nil && !t.Before(aNotBefore) {
				expDates = append(expDates, info.Name())
				return filepath.SkipDir
			}
		}
		return nil
	})

	return expDates, err
}

func (db *DiskDatabase) ListIssuersForExpirationDate(expDate string) ([]string, error) {
	issuers := make([]string, 0)

	err := filepath.Walk(filepath.Join(db.rootPath, expDate), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			glog.Warningf("prevent panic by handling failure accessing a path %q: %v", path, err)
			return err
		}
		if strings.HasSuffix(info.Name(), kSuffixCertificates) {
			issuers = append(issuers, strings.TrimSuffix(info.Name(), kSuffixCertificates))
		}
		return nil
	})

	return issuers, err
}

func (db *DiskDatabase) ReconstructIssuerMetadata(expDate string, issuer string) error {
	pemPath := filepath.Join(db.rootPath, expDate, fmt.Sprintf("%s%s", issuer, kSuffixCertificates))

	fd, err := os.Open(pemPath)
	if err != nil {
		return err
	}

	cacheEntry, err := NewCacheEntry(fd, pemPath, db.permissions)
	if err != nil {
		return err
	}
	defer cacheEntry.Close()

	scanner := bufio.NewScanner(fd)
	scanBuffer := make([]byte, 0, 512*1024)
	scanner.Buffer(scanBuffer, cap(scanBuffer))

	// Splits on the end of a PEM CERTIFICATE, won't work for non-CERTIFICATE
	// objects
	split := func(data []byte, atEOF bool) (int, []byte, error) {
		if data != nil && len(data) > len(kPemEndCert) {

			offset := bytes.Index(data, kPemEndCert)

			if offset >= 0 {
				totalLength := offset + len(kPemEndCert)
				token := data[:totalLength]
				return totalLength, token, nil
			}
		}

		return 0, nil, nil
	}
	scanner.Split(split)

	for {
		if !scanner.Scan() {
			return scanner.Err()
		}

		block, rest := pem.Decode(scanner.Bytes())

		if block == nil {
			glog.Infof("%s: Not a valid PEM.", pemPath)
			glog.Info(hex.Dump(rest))
			continue
		}

		if len(rest) != 0 {
			err := fmt.Errorf("PEM Scanner failure, should have been an exact PEM. Rest=%s, Buf=%s", hex.Dump(rest), hex.Dump(scanner.Bytes()))
			return err
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			glog.Warningf("%s: Couldn't parse certificate: %v", pemPath, err)
			glog.Warningf("%s: Cert bytes: %s", pemPath, hex.Dump(scanner.Bytes()))
			continue
		}

		cacheEntry.meta.Accumulate(cert)

		unknown, err := cacheEntry.known.WasUnknown(cert.SerialNumber)
		if err != nil {
			glog.Warningf("%s: Couldn't check known status of certificate: %v", pemPath, err)
			glog.Warningf("%s: Cert bytes: %s", pemPath, hex.Dump(scanner.Bytes()))
			continue
		}

		if unknown {
			glog.Warningf("%s: Certificate was unknown %v", pemPath, cert.SerialNumber)
		}
	}
}

func (db *DiskDatabase) SaveLogState(aLogObj *CertificateLog) error {
	filename := base64.URLEncoding.EncodeToString([]byte(aLogObj.URL))
	dirPath := filepath.Join(db.rootPath, kStateDirName)
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
	filePath := filepath.Join(db.rootPath, kStateDirName, filename)

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

func (db *DiskDatabase) getPathForID(aExpiration *time.Time, aSKI []byte, aAKI AKI) (string, string) {
	subdirName := aExpiration.Format(kExpirationFormat)
	dirPath := filepath.Join(db.rootPath, subdirName)

	issuerName := aAKI.ID()
	fileName := fmt.Sprintf("%s%s", issuerName, kSuffixCertificates)
	filePath := filepath.Join(dirPath, fileName)
	return dirPath, filePath
}

func (db *DiskDatabase) markDirty(aExpiration *time.Time) error {
	subdirName := aExpiration.Format(kExpirationFormat)
	dirPath := filepath.Join(db.rootPath, subdirName)
	filePath := filepath.Join(dirPath, "dirty")

	_, err := os.Stat(filePath)
	if err != nil && os.IsNotExist(err) {
		return ioutil.WriteFile(filePath, []byte{}, 0666)
	}
	return nil
}

func getSpki(aCert *x509.Certificate) []byte {
	if len(aCert.SubjectKeyId) < 8 {
		digest := sha1.Sum(aCert.RawSubjectPublicKeyInfo)

		glog.Warningf("[issuer: %s] SPKI is short: %v, using %v instead.", aCert.Issuer.String(), aCert.SubjectKeyId, digest[0:])
		return digest[0:]
	}

	return aCert.SubjectKeyId
}

func (db *DiskDatabase) Store(aCert *x509.Certificate, aLogURL string) error {
	spki := getSpki(aCert)
	dirPath, filePath := db.getPathForID(&aCert.NotAfter, spki, AKI{aCert.AuthorityKeyId})
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
			ce.meta.Accumulate(aCert)
			err = pem.Encode(ce.fd, &pemblock)
			ce.mutex.Unlock()
		}

		if err == nil {
			break
		}
	}

	if err != nil {
		glog.Errorf("Cache eviction collision: %s", err)
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
