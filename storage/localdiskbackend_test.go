package storage

import (
	"bytes"
	"context"
	"encoding/hex"
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
	db := NewLocalDiskBackend(0644, rootFolder)
	cache := NewMockRemoteCache()
	return &LocalDiskTestHarness{t, rootFolder, db, cache}
}

type LocalDiskTestHarness struct {
	t     *testing.T
	root  string
	db    StorageBackend
	cache RemoteCache
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

func Test_KnownCertificateList(t *testing.T) {
	h := makeLocalDiskHarness(t)
	defer h.cleanup()

	issuer := NewIssuerFromString("issuerAKI")
	serials := []Serial{NewSerialFromHex("01"), NewSerialFromHex("02"), NewSerialFromHex("03")}

	err := h.db.StoreKnownCertificateList(context.TODO(), issuer, serials)
	if err != nil {
		t.Error(err)
	}

	fileBytes, err := ioutil.ReadFile(filepath.Join(h.root, issuer.ID()))
	if err != nil {
		t.Error(err)
	}

	expected, err := hex.DecodeString("30310A30320A30330A")
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(expected, fileBytes) {
		t.Fatalf("Data should match exactly - expected=[%+v] loaded=[%+v]", expected, fileBytes)
	}
}
