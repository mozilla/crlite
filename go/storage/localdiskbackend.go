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

	"github.com/mozilla/crlite/go"
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
	aNotBefore time.Time) ([]types.ExpDate, error) {
	expDates := make([]types.ExpDate, 0)

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

			expDate, err := types.NewExpDate(info.Name())
			if err == nil && !expDate.IsExpiredAt(aNotBefore) {
				expDates = append(expDates, expDate)
				return filepath.SkipDir
			}
		}
		return nil
	})

	return expDates, err
}

func (db *LocalDiskBackend) ListIssuersForExpirationDate(_ context.Context,
	expDate types.ExpDate) ([]types.Issuer, error) {
	issuers := make([]types.Issuer, 0)

	err := filepath.Walk(filepath.Join(db.rootPath, expDate.ID()), func(path string, info os.FileInfo,
		err error) error {
		if err != nil {
			glog.Warningf("prevent panic by handling failure accessing a path %q: %v", path, err)
			return err
		}
		if strings.HasSuffix(info.Name(), kSuffixCertificates) {
			id := strings.TrimSuffix(info.Name(), kSuffixCertificates)
			issuers = append(issuers, types.NewIssuerFromString(id))
		}
		return nil
	})

	return issuers, err
}

func (db *LocalDiskBackend) ListSerialsForExpirationDateAndIssuer(ctx context.Context,
	expDate types.ExpDate, issuer types.Issuer) ([]types.Serial, error) {
	defer metrics.MeasureSince([]string{"ListSerialsForExpirationDateAndIssuer"}, time.Now())
	serials := make([]types.Serial, 0)
	serialChan := make(chan types.UniqueCertIdentifier, 1*1024*1024)
	quitChan := make(chan struct{})

	err := db.StreamSerialsForExpirationDateAndIssuer(ctx, expDate, issuer, quitChan, serialChan)
	if err != nil {
		return serials, err
	}
	close(serialChan)

	for tuple := range serialChan {
		serials = append(serials, tuple.SerialNum)
	}

	return serials, nil
}

func (db *LocalDiskBackend) StreamSerialsForExpirationDateAndIssuer(_ context.Context,
	expDate types.ExpDate, issuer types.Issuer, _ <-chan struct{}, sChan chan<- types.UniqueCertIdentifier) error {

	return filepath.Walk(filepath.Join(db.rootPath, expDate.ID(), issuer.ID()), func(path string,
		info os.FileInfo, err error) error {
		if err != nil {
			glog.Warningf("prevent panic by handling failure accessing a path %q: %v", path, err)
			return err
		}
		if strings.HasSuffix(info.Name(), kSuffixCertificates) {
			id := strings.TrimSuffix(info.Name(), kSuffixCertificates)
			// TODO: read file, pull out serials -- this isn't right
			serial, err := types.NewSerialFromIDString(id)
			if err != nil {
				return err
			}
			sChan <- types.UniqueCertIdentifier{
				SerialNum: serial,
				Issuer:    issuer,
				ExpDate:   expDate,
			}
			return fmt.Errorf("Unimplemented")
		}
		return nil
	})
}

func (db *LocalDiskBackend) AllocateExpDateAndIssuer(_ context.Context, expDate types.ExpDate,
	issuer types.Issuer) error {
	path := filepath.Join(db.rootPath, expDate.ID(), issuer.ID())
	return makeDirectoryIfNotExist(path)
}

func (db *LocalDiskBackend) StoreCertificatePEM(_ context.Context, serial types.Serial, expDate types.ExpDate,
	issuer types.Issuer, b []byte) error {
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

func (db *LocalDiskBackend) StoreKnownCertificateList(ctx context.Context, issuer types.Issuer,
	serials []types.Serial) error {
	path := filepath.Join(db.rootPath, issuer.ID())
	if err := makeDirectoryIfNotExist(path); err != nil {
		return err
	}

	fd, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, db.perms)
	if err != nil {
		return err
	}

	defer fd.Close()
	for _, s := range serials {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			_, err := fd.Write([]byte(s.HexString() + "\n"))
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (db *LocalDiskBackend) LoadCertificatePEM(_ context.Context, serial types.Serial, expDate types.ExpDate,
	issuer types.Issuer) ([]byte, error) {
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

func (db *LocalDiskBackend) LoadAllLogStates(_ context.Context) ([]CertificateLog, error) {
	return nil, fmt.Errorf("Unimplemented")
}
