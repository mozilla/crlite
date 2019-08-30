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
	db := NewLocalDiskBackend(0644, rootFolder)
	return &LocalDiskTestHarness{t, rootFolder, db}
}

type LocalDiskTestHarness struct {
	t    *testing.T
	root string
	db   StorageBackend
}

func (h *LocalDiskTestHarness) Remove(id string) {
	if err := os.RemoveAll(id); err != nil {
		h.t.Fatalf("Couldn't remove %s: %+v", id, err)
	}
}

func (h *LocalDiskTestHarness) cleanup() {
	h.Remove(h.root)
}

func Test_LocalDiskStoreLoad(t *testing.T) {
	t.Skip("Disabled")
	h := makeLocalDiskHarness(t)
	defer h.cleanup()
	BackendTestStoreLoad(t, h.db)
}

func Test_LocalDiskListFiles(t *testing.T) {
	t.Skip("Disabled")
	h := makeLocalDiskHarness(t)
	defer h.cleanup()
	BackendTestListFiles(t, h.db)
}

func Test_LocalDiskLogState(t *testing.T) {
	h := makeLocalDiskHarness(t)
	defer h.cleanup()
	BackendTestLogState(t, h.db)
}

func Test_LocalDiskKnownCertificates(t *testing.T) {
	h := makeLocalDiskHarness(t)
	defer h.cleanup()
	BackendTestKnownCertificates(t, h.db)
}

func Test_LocalDiskIssuerMetadata(t *testing.T) {
	h := makeLocalDiskHarness(t)
	defer h.cleanup()
	BackendTestIssuerMetadata(t, h.db)
}
