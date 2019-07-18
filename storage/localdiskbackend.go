package storage

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
)

type LocalDiskBackend struct {
	perms os.FileMode
}

func NewLocalDiskBackend(perms os.FileMode) StorageBackend {
	return &LocalDiskBackend{perms}
}

func isDirectory(aPath string) bool {
	fileStat, err := os.Stat(aPath)
	if err != nil {
		return false
	}

	return fileStat.IsDir()
}

func (db *LocalDiskBackend) Store(id string, data []byte) error {
	dirPath, _ := filepath.Split(id)

	if !isDirectory(dirPath) {
		err := os.MkdirAll(dirPath, os.ModeDir|0777)
		if err != nil {
			return err
		}
	}

	fd, err := os.OpenFile(id, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, db.perms)
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

func (db *LocalDiskBackend) Load(id string) ([]byte, error) {
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

func (db *LocalDiskBackend) List(path string, walkFn filepath.WalkFunc) error {
	return filepath.Walk(path, walkFn)
}

func (db *LocalDiskBackend) Writer(id string, append bool) (io.WriteCloser, error) {
	flags := os.O_WRONLY | os.O_CREATE
	if append {
		flags = flags | os.O_APPEND
	} else {
		flags = flags | os.O_TRUNC
	}

	return os.OpenFile(id, flags, db.perms)
}

func (db *LocalDiskBackend) ReadWriter(id string) (io.ReadWriteCloser, error) {
	return os.OpenFile(id, os.O_RDWR|os.O_CREATE, db.perms)
}
