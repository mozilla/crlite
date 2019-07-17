package storage

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

type DiskBackend struct {
	perms os.FileMode
}

func NewDiskBackend(perms os.FileMode) StorageBackend {
	return &DiskBackend{perms}
}

func (db *DiskBackend) Store(id string, data []byte) (int, error) {
	fd, err := os.OpenFile(id, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, db.perms)
	if err != nil {
		return 0, err
	}

	bytesWritten, err := fd.Write(data)
	if err != nil {
		fd.Close() // ignore error
		return bytesWritten, err
	}

	if len(data) != bytesWritten {
		return bytesWritten, fmt.Errorf("Only wrote %d of %d bytes.", bytesWritten, len(data))
	}

	err = fd.Close()
	return bytesWritten, err
}

func (db *DiskBackend) Load(id string) ([]byte, error) {
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

func (db *DiskBackend) List(path string, walkFn filepath.WalkFunc) error {
	return filepath.Walk(path, walkFn)
}
