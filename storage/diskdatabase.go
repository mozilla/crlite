package storage

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/google/certificate-transparency/go/x509"
)

type DiskDatabase struct {
	rootDir     *os.File
	permissions os.FileMode
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

	fileObj, err := os.Open(aPath)
	if err != nil {
		return nil, err
	}

	db := &DiskDatabase{
		rootDir:     fileObj,
		permissions: aPerms,
	}

	return db, nil
}

func (db *DiskDatabase) SaveLogState(aLogObj *CertificateLog) error {
	// TODO
	return nil
}

func (db *DiskDatabase) GetLogState(aUrl string) (*CertificateLog, error) {
	// TODO
	var certLogObj CertificateLog
	return &certLogObj, nil
}

func (db *DiskDatabase) getPathForID(aExpiration *time.Time, aSKI []byte, aAKI []byte) (string, string) {
	subdirName := aExpiration.Format("2006-01-02")
	issuerName := base64.URLEncoding.EncodeToString(aAKI)
	dirPath := filepath.Join(db.rootDir.Name(), subdirName, issuerName)

	subjectName := base64.URLEncoding.EncodeToString(aSKI)
	filePath := filepath.Join(dirPath, subjectName)
	return dirPath, filePath
}

func (db *DiskDatabase) Store(aCert *x509.Certificate) error {
	dirPath, filePath := db.getPathForID(&aCert.NotAfter, aCert.AuthorityKeyId, aCert.SubjectKeyId)
	if !isDirectory(dirPath) {
		err := os.MkdirAll(dirPath, os.ModeDir|0777)
		if err != nil {
			return err
		}
	}
	_, err := os.Stat(filePath)
	if err != nil && os.IsNotExist(err) {
		return ioutil.WriteFile(filePath, aCert.Raw, db.permissions)
	}
	// Already exists, so skip
	return nil
}
