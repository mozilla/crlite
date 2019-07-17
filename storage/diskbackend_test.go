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
	err := db.Store(path, data)
	if err != nil {
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

func Test_ListFiles(t *testing.T) {
	folder, err := ioutil.TempDir("", t.Name())
	if err != nil {
		t.Error(err)
	}

	defer func() {
		if err := os.RemoveAll(folder); err != nil {
			t.Fatalf("Couldn't remove %s: %+v", folder, err)
		}
	}()

	var expectedFolders []string
	var expectedFiles []string

	constructFolder := func(path string) {
		if err := os.MkdirAll(path, 0777); err != nil {
			t.Fatalf("Couldn't make directory: %+v", err)
		}
		expectedFolders = append(expectedFolders, path)
	}

	constructFile := func(path string) {
		fd, err := os.Create(path)
		if err != nil {
			t.Fatalf("Couldn't make file")
		}
		fd.Close()
		expectedFiles = append(expectedFiles, path)
	}

	constructFolder(filepath.Join(folder, "2017-11-28"))
	constructFolder(filepath.Join(folder, "2018-11-28"))
	constructFolder(filepath.Join(folder, "2019-11-28"))

	constructFile(filepath.Join(folder, "metadata.data"))
	constructFile(filepath.Join(folder, "2019-11-28", "certs.data"))

	db := NewDiskBackend(0644)
	err = db.List(folder, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		removeFromList := func(s []string, i int) []string {
			s[i] = s[len(s)-1]
			return s[:len(s)-1]
		}

		if info.IsDir() {
			for i := 0; i < len(expectedFolders); i++ {
				if path == expectedFolders[i] {
					expectedFolders = removeFromList(expectedFolders, i)
					return nil
				}
			}

			// If it's the folder we're in, that's okay
			if path == folder {
				return nil
			}
		}

		for i := 0; i < len(expectedFiles); i++ {
			if path == expectedFiles[i] {
				expectedFiles = removeFromList(expectedFiles, i)
				return nil
			}
		}

		t.Errorf("Did't find %s", path)
		return nil
	})
	if err != nil {
		t.Error(err)
	}

	if len(expectedFolders) > 0 {
		t.Errorf("Didn't find folders: %+v", expectedFolders)
	}
	if len(expectedFiles) > 0 {
		t.Errorf("Didn't find files: %+v", expectedFiles)
	}
}
