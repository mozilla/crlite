package storage

import (
	"fmt"
	"path/filepath"
)

type MockBackend struct {
	store map[string][]byte
}

func NewMockBackend() *MockBackend {
	return &MockBackend{make(map[string][]byte)}
}

func (db *MockBackend) Store(id string, data []byte) (int, error) {
	db.store[id] = data
	bytesWritten := len(data)
	return bytesWritten, nil
}

func (db *MockBackend) Load(id string) ([]byte, error) {
	data, ok := db.store[id]
	if ok {
		return data, nil
	}

	return []byte{}, fmt.Errorf("No file found")
}

func (db *MockBackend) List(path string, walkFn filepath.WalkFunc) error {
	return nil
}
