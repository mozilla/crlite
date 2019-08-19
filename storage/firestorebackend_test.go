package storage

import (
	"context"
	"fmt"
	"os"
	"testing"

	"cloud.google.com/go/firestore"
)

var kFirestoreEmulatorEnv = "FIRESTORE_EMULATOR_HOST"
var kProjectId = "test-project"

func verifyEmulator(t *testing.T) {
	setting, ok := os.LookupEnv(kFirestoreEmulatorEnv)
	if !ok {
		t.Skipf("%s is not set, unable to run %s. Skipping.", kFirestoreEmulatorEnv, t.Name())
	}
	t.Logf("Connecting to %s", setting)
}

func makeFirestoreHarness(t *testing.T) *FirestoreTestHarness {
	verifyEmulator(t)

	ctx := context.Background()

	be, err := NewFirestoreBackend(ctx, kProjectId)
	if err != nil {
		t.Fatal(err)
	}

	harnessClient, err := firestore.NewClient(ctx, kProjectId)
	if err != nil {
		t.Fatal(err)
	}

	return &FirestoreTestHarness{t, ctx, []string{}, be, harnessClient}
}

type FirestoreTestHarness struct {
	t             *testing.T
	ctx           context.Context
	folders       []string
	be            *FirestoreBackend
	harnessClient *firestore.Client
}

func (h *FirestoreTestHarness) Cleanup() {
	for i := range h.folders {
		h.Remove(h.folders[i])
	}
	h.be.Close()
	h.harnessClient.Close()
}

func (h *FirestoreTestHarness) MakeFolder(id string) string {
	fmt.Printf("MakeFolder %s\n", id)
	coll := h.harnessClient.Collection(id)
	if coll == nil {
		h.t.Errorf("Collection for %s is nil", id)
	}
	fmt.Printf("Made folder %+v\n", coll)

	h.folders = append(h.folders, id)
	return id
}

func (h *FirestoreTestHarness) MakeFile(id string, data []byte) {
	doc := h.harnessClient.Doc(id)
	if doc == nil {
		h.t.Errorf("Document for %s is nil", id)
		return
	}

	h.t.Logf("Setting %s", id)
	_, err := doc.Set(h.ctx, map[string]interface{}{kFdata: data})
	if err != nil {
		h.t.Error(err)
	}
}

func (h *FirestoreTestHarness) Remove(id string) {
	coll := h.harnessClient.Collection(id)
	if coll == nil {
		doc := h.harnessClient.Doc(id)
		if doc == nil {
			h.t.Fatalf("%s appears to neither be a Doc or Collection", id)
			return
		}
		if _, err := doc.Delete(h.ctx); err != nil {
			h.t.Error(err)
		}
	} else {
		if err := h.be.deleteCollection(coll, 64); err != nil {
			h.t.Error(err)
		}
	}
}

func Test_FirestoreBasicLoop(t *testing.T) {
	ctx := context.Background()
	verifyEmulator(t)

	c, err := firestore.NewClient(ctx, kProjectId)
	if err != nil {
		t.Fatal(err)
	}

	coll := c.Collection("My Stuff")
	doc := coll.Doc("Document")
	_, err = doc.Set(ctx, map[string]interface{}{kFdata: []byte{0xDE, 0xAD}})
	if err != nil {
		t.Fatal(err)
	}

	docsnap, err := doc.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}

	data, err := docsnap.DataAt(kFdata)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Retreived %+v from %+v", data, docsnap)

	c.Close()
}

func Test_FirestoreStoreLoad(t *testing.T) {
	h := makeFirestoreHarness(t)
	defer h.Cleanup()
	BackendTestStoreLoad(t, h.be, h)
}

// func Test_FirestoreListFiles(t *testing.T) {
// 	h := makeFirestoreHarness(t)
// 	defer h.Cleanup()
// 	BackendTestListFiles(t, h.be, h)
// }

func Test_FirestoreWriter(t *testing.T) {
	h := makeFirestoreHarness(t)
	defer h.Cleanup()
	BackendTestWriter(t, h.be, h)
}

func Test_FirestoreReadWriter(t *testing.T) {
	h := makeFirestoreHarness(t)
	defer h.Cleanup()
	BackendTestReadWriter(t, h.be, h)
}

// func Test_FirestoreAutoCreateFolders(t *testing.T) {
// 	h := makeFirestoreHarness(t)
// 	defer h.Cleanup()
// 	BackendTestAutoCreateFolders(t, h.be, h)
// }
