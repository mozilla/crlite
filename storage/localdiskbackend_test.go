package storage

import (
	"io/ioutil"
	"os"
	"testing"
)

func makeLocalDiskHarness(t *testing.T) *LocalDiskTestHarness {
	rootFolder, err := ioutil.TempDir("", t.Name())
	if err != nil {
		t.Fatal(err)
	}
	return &LocalDiskTestHarness{t, rootFolder}
}

type LocalDiskTestHarness struct {
	t    *testing.T
	root string
}

func (h *LocalDiskTestHarness) Remove(id string) {
	if err := os.RemoveAll(id); err != nil {
		h.t.Fatalf("Couldn't remove %s: %+v", id, err)
	}
}

func (h *LocalDiskTestHarness) Cleanup() {
	h.Remove(h.root)
}

func Test_LocalDiskStoreLoad(t *testing.T) {
	t.Skip("Disabled")
	h := makeLocalDiskHarness(t)
	defer h.Cleanup()
	db := NewLocalDiskBackend(0644, h.root)
	BackendTestStoreLoad(t, db)
}

func Test_LocalDiskListFiles(t *testing.T) {
	t.Skip("Disabled")
	h := makeLocalDiskHarness(t)
	defer h.Cleanup()
	db := NewLocalDiskBackend(0644, h.root)
	BackendTestListFiles(t, db)
}
