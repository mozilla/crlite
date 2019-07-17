package storage

import (
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

// type StorageBackend interface {
// 	Store(id string, b []byte) (int, error)
// 	Load(id string) ([]byte, error)
// 	List(path string, walkFn filepath.WalkFunc) error
// 	// Someday: Add Reader and Writer methods
// }

func StoreAndLoad(t *testing.T, path string, db StorageBackend, data []byte) {
	cnt, err := db.Store(path, data)
	if cnt != len(data) || err != nil {
		t.Fatalf("Should have stored %d bytes: %+v", len(data), err)
	}

	loaded, err := db.Load(path)
	if err != nil {
		t.Fatalf("Should have loaded: %+v", err)
	}

	if !bytes.Equal(data, loaded) {
		t.Fatalf("Data should match exactly")
	}
}

func Test_StoreLoad(t *testing.T) {
	folder, err := ioutil.TempDir("", t.Name())
	if err != nil {
		t.Error(err)
	}

	defer func() {
		if err := os.RemoveAll(folder); err != nil {
			t.Fatalf("Couldn't remove %s: %+v", folder, err)
		}
	}()

	path := filepath.Join(folder, "test_file")

	db := NewDiskBackend(0644)

	StoreAndLoad(t, path, db, []byte{})
	StoreAndLoad(t, path, db, []byte{0x01})
	StoreAndLoad(t, path, db, []byte{0x00, 0x01, 0x02})
	StoreAndLoad(t, path, db, make([]byte, 4*1024*1024))

	os.Remove(path)

	// Load empty
	_, err = db.Load(path)
	if err == nil {
		t.Fatalf("Should not have loaded a missing file")
	}
}
