package storage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mozilla/crlite/go"
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
