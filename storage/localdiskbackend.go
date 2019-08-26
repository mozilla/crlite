package storage

import (
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang/glog"
)

const (
	kStateDirName            = "state"
	kSuffixKnownCertificates = ".known"
	kSuffixIssuerMetadata    = ".meta"
	kSuffixCertificates      = ".pem"
	kDirtyMarker             = "dirty"
)

type LocalDiskBackend struct {
	perms    os.FileMode
	rootPath string
}

func NewLocalDiskBackend(perms os.FileMode, aPath string) StorageBackend {
	return &LocalDiskBackend{perms, aPath}
}

func isDirectory(aPath string) bool {
	fileStat, err := os.Stat(aPath)
	if err != nil {
		return false
	}

	return fileStat.IsDir()
}

func makeDirectoryIfNotExist(id string) error {
	dirPath, _ := filepath.Split(id)

	if !isDirectory(dirPath) {
		return os.MkdirAll(dirPath, os.ModeDir|0777)
	}
	return nil
}

func (db *LocalDiskBackend) store(path string, data []byte) error {
	if err := makeDirectoryIfNotExist(path); err != nil {
		return err
	}

	fd, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, db.perms)
	if err != nil {
		return err
	}

	bytesWritten, err := fd.Write(data)
	if err != nil {
		fd.Close() // ignore error
		return err
	}

	if len(data) != bytesWritten {
		return fmt.Errorf("Only wrote %d of %d bytes.", bytesWritten, len(data))
	}

	return fd.Close()
}

func (db *LocalDiskBackend) MarkDirty(id string) error {
	return db.store(filepath.Join(id, kDirtyMarker), []byte{0})
}

func (db *LocalDiskBackend) Store(docType DocumentType, id string, data []byte) error {
	// TODO: something with docType
	return db.store(id, data)
}

func (db *LocalDiskBackend) Load(docType DocumentType, id string) ([]byte, error) {
	// TODO: something with docType
	fd, err := os.Open(id)
	if err != nil {
		return []byte{}, err
	}

	data, err := ioutil.ReadAll(fd)
	if err != nil {
		fd.Close() // ignore error
		return data, err
	}

	err = fd.Close()
	return data, err
}

func (db *LocalDiskBackend) ListExpirationDates(aNotBefore time.Time) ([]string, error) {
	expDates := make([]string, 0)

	aNotBefore = time.Date(aNotBefore.Year(), aNotBefore.Month(), aNotBefore.Day(), 0, 0, 0, 0, time.UTC)

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
			if err == nil && !t.Before(aNotBefore) {
				expDates = append(expDates, info.Name())
				return filepath.SkipDir
			}
		}
		return nil
	})

	return expDates, err
}

func (db *LocalDiskBackend) ListIssuersForExpirationDate(expDate string) ([]string, error) {
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

func (db *LocalDiskBackend) Writer(id string, append bool) (io.WriteCloser, error) {
	if err := makeDirectoryIfNotExist(id); err != nil {
		return nil, err
	}

	flags := os.O_WRONLY | os.O_CREATE
	if append {
		flags = flags | os.O_APPEND
	} else {
		flags = flags | os.O_TRUNC
	}

	return os.OpenFile(id, flags, db.perms)
}

func (db *LocalDiskBackend) ReadWriter(id string) (io.ReadWriteCloser, error) {
	if err := makeDirectoryIfNotExist(id); err != nil {
		return nil, err
	}

	return os.OpenFile(id, os.O_RDWR|os.O_CREATE, db.perms)
}

func (db *LocalDiskBackend) StoreCertificatePEM(spki SPKI, expDate string, issuer string, b []byte) error {
	glog.Warningf("Need to store into " + kSuffixCertificates)
	return fmt.Errorf("Unimplemented")
}

func (db *LocalDiskBackend) StoreLogState(logURL string, log *CertificateLog) error {
	return fmt.Errorf("Unimplemented")
}

func (db *LocalDiskBackend) StoreIssuerMetadata(expDate string, issuer string, data *Metadata) error {
	glog.Warningf("Need to store into " + kSuffixIssuerMetadata)
	return fmt.Errorf("Unimplemented")
}

func (db *LocalDiskBackend) StoreIssuerKnownSerials(expDate string, issuer string, serials []*big.Int) error {
	glog.Warningf("Need to store into " + kSuffixKnownCertificates)
	return fmt.Errorf("Unimplemented")
}

func (db *LocalDiskBackend) LoadCertificatePEM(spki SPKI, expDate string, issuer string) ([]byte, error) {
	return nil, fmt.Errorf("Unimplemented")
}

func (db *LocalDiskBackend) LoadLogState(logURL string) (*CertificateLog, error) {
	return nil, fmt.Errorf("Unimplemented")
}

func (db *LocalDiskBackend) LoadIssuerMetadata(expDate string, issuer string) (*Metadata, error) {
	return nil, fmt.Errorf("Unimplemented")
}

func (db *LocalDiskBackend) LoadIssuerKnownSerials(expDate string, issuer string) ([]*big.Int, error) {
	return nil, fmt.Errorf("Unimplemented")
}
