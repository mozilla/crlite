package storage

import (
	"bufio"
	"context"
	"encoding/hex"
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

// Write a line delimited list of serial numbers and reason codes to a text
// file. Each line contains hex encoded binary data. The first (encoded) byte
// in each line is the reason code. The remaining bytes are the serial number.
func (db *LocalDiskBackend) StoreRevokedCertificateList(ctx context.Context, issuer types.Issuer,
	serials []types.SerialAndReason) error {
	path := filepath.Join(db.rootPath, issuer.ID())
	if err := makeDirectoryIfNotExist(path); err != nil {
		return err
	}

	fd, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, db.perms)
	if err != nil {
		return err
	}
	defer fd.Close()

	writer := bufio.NewWriter(fd)
	defer writer.Flush()

	for _, s := range serials {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			_, err = writer.WriteString(hex.EncodeToString([]byte{s.Reason}))
			if err != nil {
				return err
			}
			_, err := writer.WriteString(s.Serial.HexString())
			if err != nil {
				return err
			}
			err = writer.WriteByte('\n')
			if err != nil {
				return err
			}
		}
	}
	return nil
}
