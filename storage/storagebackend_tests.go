package storage

import (
	"bytes"
	"io"
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

type BackendTestHarness interface {
	BaseFolder() string
	MakeFolder(id string) string
	MakeFile(id string, data []byte) string
	Remove(id string)
}

func storeAndLoad(t *testing.T, docType DocumentType, path string, db StorageBackend, data []byte) {
	err := db.Store(docType, path, data)
	if err != nil {
		t.Fatalf("Should have stored %d bytes: %+v", len(data), err)
	}

	t.Logf("Now loading %s", path)

	loaded, err := db.Load(docType, path)
	if err != nil {
		t.Fatalf("Should have loaded: %+v", err)
	}

	if !bytes.Equal(data, loaded) {
		t.Fatalf("Data should match exactly")
	}
}

func BackendTestStoreLoad(t *testing.T, db StorageBackend, h BackendTestHarness) {
	path := filepath.Join(h.MakeFolder(t.Name()), "test_file")

	storeAndLoad(t, TypeLogState, path, db, []byte{})
	storeAndLoad(t, TypeIssuerMetadata, path, db, []byte{0x01})
	storeAndLoad(t, TypeIssuerKnownSerials, path, db, []byte{0x00, 0x01, 0x02})
	storeAndLoad(t, TypeCertificatePEMList, path, db, make([]byte, 1*1024*1024))
	// storeAndLoad(t, TypeCertificatePEMList, path, db, make([]byte, 4*1024*1024)) // TODO too big for firestore

	h.Remove(path)

	// Load empty
	_, err := db.Load(TypeLogState, path)
	if err == nil {
		t.Fatalf("Should not have loaded a missing file")
	}
}

func BackendTestListFiles(t *testing.T, db StorageBackend, h BackendTestHarness) {
	var expectedFolders []string
	var expectedFiles []string

	// Note: Firestore forbids empty collections
	expectedFolders = append(expectedFolders, h.MakeFolder("2017-11-28"))
	expectedFolders = append(expectedFolders, h.MakeFolder("2018-11-28"))
	expectedFolders = append(expectedFolders, h.MakeFolder("2019-11-28"))
	expectedFolders = append(expectedFolders, h.MakeFolder("meta"))
	expectedFiles = append(expectedFiles, h.MakeFile(filepath.Join("meta", "metadata.data"), []byte{0x42}))
	expectedFiles = append(expectedFiles, h.MakeFile(filepath.Join("2019-11-28", "certs.data"), []byte{0xDA, 0xDA}))

	folder := h.BaseFolder()
	err := db.List(folder, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		removeFromList := func(s []string, i int) []string {
			s[i] = s[len(s)-1]
			return s[:len(s)-1]
		}

		// If it's the folder we're in, that's okay
		if path == folder {
			return nil
		}

		if info.IsDir() {
			for i := 0; i < len(expectedFolders); i++ {
				if path == expectedFolders[i] {
					expectedFolders = removeFromList(expectedFolders, i)
					return nil
				}
			}
		}

		for i := 0; i < len(expectedFiles); i++ {
			if path == expectedFiles[i] {
				expectedFiles = removeFromList(expectedFiles, i)
				return nil
			}
		}

		t.Errorf("Did't find %s (%s) %+v", path, folder, info)
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

func BackendTestWriter(t *testing.T, db StorageBackend, h BackendTestHarness) {
	folder := h.MakeFolder(t.Name())
	path := filepath.Join(folder, "metadata.data")

	verifyText := func(text string) {
		data, err := db.Load(TypeBulk, path)
		if err != nil {
			t.Error(err)
		}
		if string(data) != text {
			t.Errorf("Expected to read [%s] but found [%s]", text, data)
		}
	}

	truncWriter, err := db.Writer(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.WriteString(truncWriter, "This is a string\n"); err != nil {
		t.Error(err)
	}
	truncWriter.Close()

	verifyText("This is a string\n")

	truncWriter, err = db.Writer(path, false)
	if err != nil {
		t.Error(err)
	}
	if _, err = io.WriteString(truncWriter, "This is another string\n"); err != nil {
		t.Error(err)
	}
	truncWriter.Close()

	verifyText("This is another string\n")

	appendWriter, err := db.Writer(path, true)
	if err != nil {
		t.Error(err)
	}
	if _, err = io.WriteString(appendWriter, "appended to the first\n"); err != nil {
		t.Error(err)
	}
	appendWriter.Close()

	verifyText("This is another string\nappended to the first\n")
}

func BackendTestReadWriter(t *testing.T, db StorageBackend, h BackendTestHarness) {
	folder := h.MakeFolder(t.Name())
	path := filepath.Join(folder, "metadata.data")

	verifyText := func(in io.Reader, text string) {
		data, err := ioutil.ReadAll(in)
		if err != nil {
			t.Error(err)
		}
		if string(data) != text {
			t.Errorf("Expected to read [%s] but found [%s]", text, data)
		}
	}

	appendWriter, err := db.ReadWriter(path)
	if err != nil {
		t.Fatal(err)
	}

	verifyText(appendWriter, "")
	if _, err = io.WriteString(appendWriter, "One"); err != nil {
		t.Error(err)
	}
	appendWriter.Close()

	appendWriter, err = db.ReadWriter(path)
	if err != nil {
		t.Error(err)
	}
	verifyText(appendWriter, "One")
	if _, err = io.WriteString(appendWriter, ", Two"); err != nil {
		t.Error(err)
	}
	appendWriter.Close()

	appendWriter, err = db.ReadWriter(path)
	if err != nil {
		t.Error(err)
	}
	verifyText(appendWriter, "One, Two")
	if _, err = io.WriteString(appendWriter, ", Three"); err != nil {
		t.Error(err)
	}
	appendWriter.Close()

	appendWriter, err = db.ReadWriter(path)
	if err != nil {
		t.Error(err)
	}
	verifyText(appendWriter, "One, Two, Three")
	appendWriter.Close()
}

func BackendTestAutoCreateFolders(t *testing.T, db StorageBackend, h BackendTestHarness) {
	folder := h.MakeFolder(t.Name())
	readwriterpath := filepath.Join(folder, "ReadWriter/file")
	readwriter, err := db.ReadWriter(readwriterpath)
	if err != nil {
		t.Error(err)
	}
	defer readwriter.Close()

	writerpath := filepath.Join(folder, "Writer/file")
	writer, err := db.Writer(writerpath, false)
	if err != nil {
		t.Error(err)
	}
	defer writer.Close()

	storepath := filepath.Join(folder, "Store/file")
	if err := db.Store(TypeBulk, storepath, []byte{}); err != nil {
		t.Error(err)
	}
}
