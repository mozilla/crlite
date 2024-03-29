package storage

import (
	"bytes"
	"context"
	"encoding/hex"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/mozilla/crlite/go"
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

func Test_KnownCertificateList(t *testing.T) {
	h := makeLocalDiskHarness(t)
	defer h.cleanup()

	issuer := types.NewIssuerFromString("issuerAKI")
	serials := []types.Serial{types.NewSerialFromHex("01"), types.NewSerialFromHex("02"), types.NewSerialFromHex("03")}

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
