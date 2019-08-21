package storage

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func makeLocalDiskHarness(t *testing.T) *LocalDiskTestHarness {
	rootFolder, err := ioutil.TempDir("", t.Name())
	if err != nil {
		t.Fatal(err)
	}
	return &LocalDiskTestHarness{t, rootFolder, []string{}}
}

type LocalDiskTestHarness struct {
	t       *testing.T
	root    string
	folders []string
}

func (h *LocalDiskTestHarness) Cleanup() {
	for i := range h.folders {
		h.Remove(h.folders[i])
	}
	h.Remove(h.root)
}

func (h *LocalDiskTestHarness) BaseFolder() string {
	return h.root
}

func (h *LocalDiskTestHarness) MakeFolder(id string) string {
	folder := filepath.Join(h.root, id)
	if err := os.MkdirAll(folder, 0700); err != nil {
		h.t.Fatal(err)
	}

	h.folders = append(h.folders, folder)
	return folder
}

func (h *LocalDiskTestHarness) MakeFile(id string, data []byte) string {
	file := filepath.Join(h.root, id)
	if err := ioutil.WriteFile(file, data, 0600); err != nil {
		h.t.Fatal(err)
	}
	return file
}

func (h *LocalDiskTestHarness) Remove(id string) {
	if err := os.RemoveAll(id); err != nil {
		h.t.Fatalf("Couldn't remove %s: %+v", id, err)
	}
}

func Test_LocalDiskStoreLoad(t *testing.T) {
	h := makeLocalDiskHarness(t)
	defer h.Cleanup()
	db := NewLocalDiskBackend(0644)
	BackendTestStoreLoad(t, db, h)
}

func Test_LocalDiskListFiles(t *testing.T) {
	h := makeLocalDiskHarness(t)
	defer h.Cleanup()
	db := NewLocalDiskBackend(0644)
	BackendTestListFiles(t, db, h)
}

func Test_LocalDiskWriter(t *testing.T) {
	h := makeLocalDiskHarness(t)
	defer h.Cleanup()
	db := NewLocalDiskBackend(0644)
	BackendTestWriter(t, db, h)
}

func Test_LocalDiskReadWriter(t *testing.T) {
	h := makeLocalDiskHarness(t)
	defer h.Cleanup()
	db := NewLocalDiskBackend(0644)
	BackendTestReadWriter(t, db, h)
}

func Test_LocalDiskAutoCreateFolders(t *testing.T) {
	h := makeLocalDiskHarness(t)
	defer h.Cleanup()
	db := NewLocalDiskBackend(0644)
	BackendTestAutoCreateFolders(t, db, h)
}
