package storage

import (
	"context"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"cloud.google.com/go/firestore"
	"google.golang.org/api/iterator"
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

func (h *FirestoreTestHarness) BaseFolder() string {
	return "test/doc"
}

func (h *FirestoreTestHarness) MakeFolder(id string) string {
	path := filepath.Join(h.BaseFolder(), id)
	coll := h.harnessClient.Collection(path)
	if coll == nil {
		h.t.Errorf("Collection for %s is nil -- Firestore requires collection/doc/collection/doc", id)
	}
	h.t.Logf("Made collection %+s\n", path)

	h.folders = append(h.folders, path)
	return path
}

func (h *FirestoreTestHarness) MakeFile(id string, data []byte) string {
	path := filepath.Join(h.BaseFolder(), id)
	doc := h.harnessClient.Doc(path)
	if doc == nil {
		h.t.Errorf("Document for %s is nil -- Firestore requires collection/doc/collection/doc", id)
	}

	_, err := doc.Set(h.ctx, map[string]interface{}{kFdata: data})
	if err != nil {
		h.t.Errorf("Failed to make file %s: %v", path, err)
	}

	h.t.Logf("Made document %s with %d bytes of data", path, len(data))
	return path
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

func Test_FirestoreCollectionHeirarchy(t *testing.T) {
	ctx := context.Background()
	verifyEmulator(t)

	c, err := firestore.NewClient(ctx, kProjectId)
	if err != nil {
		t.Fatal(err)
	}

	coll := c.Collection("data")
	certsDoc := coll.Doc("2034-06-16:issuerAKI.certs")
	metaDoc := coll.Doc("2034-06-16:issuerAKI.meta")
	knownDoc := coll.Doc("2034-06-16:issuerAKI.known")

	_, err = certsDoc.Set(ctx, map[string]interface{}{
		"type": "certs",
		kFdata: []byte{0xDE, 0xAD},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = metaDoc.Set(ctx, map[string]interface{}{
		"type":   "meta",
		"issuer": "the issuer",
		"crls":   []string{"http://issuer/crl"},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = knownDoc.Set(ctx, map[string]interface{}{
		"type":    "known",
		"serials": []*big.Int{big.NewInt(4), big.NewInt(3), big.NewInt(2), big.NewInt(1)},
	})
	if err != nil {
		t.Fatal(err)
	}

	// list
	collection := c.Collection("data")
	t.Logf("Collection: %s - %+v", collection.ID, collection)

	iter := collection.Where("type", "==", "date").Documents(ctx)
	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil || doc == nil {
			t.Fatal(err)
		}

		t.Logf("List: %s - %+v", doc.Ref.ID, doc)

	}

	c.Close()
}

func Test_FirestoreCollectionsGet(t *testing.T) {
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

	{
		x, err := coll.DocumentRefs(ctx).GetAll()
		t.Logf("MyStuff: %+v %+v", x, err)
	}
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
