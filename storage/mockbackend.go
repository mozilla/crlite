package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type MockBackend struct {
	store map[string][]byte
}

func NewMockBackend() *MockBackend {
	return &MockBackend{make(map[string][]byte)}
}

func (db *MockBackend) Store(id string, data []byte) error {
	db.store[id] = data
	return nil
}

func (db *MockBackend) Load(id string) ([]byte, error) {
	data, ok := db.store[id]
	if ok {
		return data, nil
	}

	return []byte{}, fmt.Errorf("No file found")
}

func (db *MockBackend) List(path string, walkFn filepath.WalkFunc) error {
	var skipList []string
	var dirsSeenList []string

	isPresent := func(needle string, haystack []string) bool {
		for i := range haystack {
			if needle == haystack[i] {
				return true
			}
		}
		return false
	}

	appendIfSkipDir := func(err error, dir string, list []string) []string {
		if err == filepath.SkipDir {
			return append(list, dir)
		}
		return list
	}

	for path, data := range db.store {
		dir, file := filepath.Split(path)

		if isPresent(dir, skipList) {
			continue
		}

		if !isPresent(dir, dirsSeenList) {
			// Walk this dir first
			dirsSeenList = append(dirsSeenList, dir)

			// Walking dirs needs the dir without the trailing separator
			dirNoSep := dir[:len(dir)-1]

			fileinfo := &MockFileInfo{dirNoSep, 0, true}
			result := walkFn(dirNoSep, fileinfo, nil)

			skipList = appendIfSkipDir(result, dir, skipList)

			if result == filepath.SkipDir {
				// If this dir said skip, skip the first file of it
				continue
			}
		}

		isDir := file == ""
		fileinfo := &MockFileInfo{path, int64(len(data)), isDir}

		result := walkFn(path, fileinfo, nil)
		skipList = appendIfSkipDir(result, dir, skipList)

	}
	return nil
}

type MockFileInfo struct {
	name  string
	size  int64
	isDir bool
}

func (mfi *MockFileInfo) Name() string {
	return mfi.name
}

func (mfi *MockFileInfo) Size() int64 {
	return mfi.size
}

func (mfi *MockFileInfo) Mode() os.FileMode {
	return 0644
}

func (mfi *MockFileInfo) ModTime() time.Time {
	return time.Now()
}

func (mfi *MockFileInfo) IsDir() bool {
	return mfi.isDir
}

func (mfi *MockFileInfo) Sys() interface{} {
	return nil
}
