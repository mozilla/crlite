package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/armon/go-metrics"
	"github.com/golang/glog"
)

const (
	kStateDirName       = "state"
	kSuffixCertificates = ".pem"
	kDirtyMarker        = "dirty"
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

func (db *LocalDiskBackend) load(path string) ([]byte, error) {
	fd, err := os.Open(path)
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

func (db *LocalDiskBackend) MarkDirty(id string) error {
	return db.store(filepath.Join(id, kDirtyMarker), []byte{0})
}

func (db *LocalDiskBackend) ListExpirationDates(_ context.Context,
	aNotBefore time.Time) ([]string, error) {
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

func (db *LocalDiskBackend) ListIssuersForExpirationDate(_ context.Context,
	expDate string) ([]Issuer, error) {
	issuers := make([]Issuer, 0)

	err := filepath.Walk(filepath.Join(db.rootPath, expDate), func(path string, info os.FileInfo,
		err error) error {
		if err != nil {
			glog.Warningf("prevent panic by handling failure accessing a path %q: %v", path, err)
			return err
		}
		if strings.HasSuffix(info.Name(), kSuffixCertificates) {
			id := strings.TrimSuffix(info.Name(), kSuffixCertificates)
			issuers = append(issuers, NewIssuerFromString(id))
		}
		return nil
	})

	return issuers, err
}

func (db *LocalDiskBackend) ListSerialsForExpirationDateAndIssuer(ctx context.Context,
	expDate string, issuer Issuer) ([]Serial, error) {
	defer metrics.MeasureSince([]string{"ListSerialsForExpirationDateAndIssuer"}, time.Now())
	serials := make([]Serial, 0)

	serialChan, err := db.StreamSerialsForExpirationDateAndIssuer(ctx, expDate, issuer)
	if err != nil {
		return serials, err
	}

	for serial := range serialChan {
		serials = append(serials, serial)
	}

	return serials, nil
}

func (db *LocalDiskBackend) StreamSerialsForExpirationDateAndIssuer(_ context.Context,
	expDate string, issuer Issuer) (<-chan Serial, error) {
	sChan := make(chan Serial)

	err := filepath.Walk(filepath.Join(db.rootPath, expDate, issuer.ID()), func(path string,
		info os.FileInfo, err error) error {
		if err != nil {
			glog.Warningf("prevent panic by handling failure accessing a path %q: %v", path, err)
			return err
		}
		if strings.HasSuffix(info.Name(), kSuffixCertificates) {
			id := strings.TrimSuffix(info.Name(), kSuffixCertificates)
			// TODO: read file, pull out serials -- this isn't right
			serial, err := NewSerialFromIDString(id)
			if err != nil {
				return err
			}
			sChan <- serial
			return fmt.Errorf("Unimplemented")
		}
		return nil
	})

	return sChan, err
}

func (db *LocalDiskBackend) AllocateExpDateAndIssuer(_ context.Context, expDate string,
	issuer Issuer) error {
	path := filepath.Join(db.rootPath, expDate, issuer.ID())
	return makeDirectoryIfNotExist(path)
}

func (db *LocalDiskBackend) StoreCertificatePEM(_ context.Context, serial Serial, expDate string,
	issuer Issuer, b []byte) error {
	glog.Warningf("Need to store into " + kSuffixCertificates)
	return fmt.Errorf("Unimplemented")
}

func (db *LocalDiskBackend) StoreLogState(_ context.Context, log *CertificateLog) error {
	path := filepath.Join(db.rootPath, kStateDirName, log.ID())

	encoded, err := json.Marshal(log)
	if err != nil {
		return err
	}

	return db.store(path, encoded)
}

func (db *LocalDiskBackend) StoreKnownCertificateList(_ context.Context, useType SerialUseType,
	issuer Issuer, serials []Serial) error {
	path := filepath.Join(db.rootPath, useType.ID(), issuer.ID())
	if err := makeDirectoryIfNotExist(path); err != nil {
		return err
	}

	encoded, err := json.Marshal(serials)
	if err != nil {
		return err
	}

	return db.store(path, encoded)
}

func (db *LocalDiskBackend) LoadCertificatePEM(_ context.Context, serial Serial, expDate string,
	issuer Issuer) ([]byte, error) {
	return nil, fmt.Errorf("Unimplemented")
}

func (db *LocalDiskBackend) LoadLogState(_ context.Context, logURL string) (*CertificateLog, error) {
	id := CertificateLogIDFromShortURL(logURL)
	path := filepath.Join(db.rootPath, kStateDirName, id)

	data, err := db.load(path)
	if err != nil {
		return &CertificateLog{
			ShortURL: logURL,
		}, nil
	}

	var log CertificateLog
	if err = json.Unmarshal(data, &log); err != nil {
		return nil, err
	}

	return &log, nil
}
