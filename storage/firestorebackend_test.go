package storage

import (
	"context"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"cloud.google.com/go/firestore"
	"google.golang.org/api/iterator"
)

var kFirestoreEmulatorEnv = "FIRESTORE_EMULATOR_HOST"

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

	projectName := fmt.Sprintf("test-%d", time.Now().Unix())

	be, err := NewFirestoreBackend(ctx, projectName)
	if err != nil {
		t.Fatal(err)
	}

	harnessClient, err := firestore.NewClient(ctx, projectName)
	if err != nil {
		t.Fatal(err)
	}

	return &FirestoreTestHarness{t, ctx, be, harnessClient}
}

type FirestoreTestHarness struct {
	t             *testing.T
	ctx           context.Context
	be            *FirestoreBackend
	harnessClient *firestore.Client
}

func (h *FirestoreTestHarness) cleanup() {
	h.be.Close()
	h.harnessClient.Close()
}

func Test_FirestoreBasicLoop(t *testing.T) {
	ctx := context.Background()
	verifyEmulator(t)

	h := makeFirestoreHarness(t)
	defer h.cleanup()

	coll := h.harnessClient.Collection("My Stuff")
	doc := coll.Doc("Document")
	_, err := doc.Set(ctx, map[string]interface{}{kFieldData: []byte{0xDE, 0xAD}})
	if err != nil {
		t.Fatal(err)
	}

	docsnap, err := doc.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}

	data, err := docsnap.DataAt(kFieldData)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Retreived %+v from %+v", data, docsnap)
}

func Test_FirestoreCollectionHeirarchy(t *testing.T) {
	ctx := context.Background()
	verifyEmulator(t)

	h := makeFirestoreHarness(t)
	defer h.cleanup()

	coll := h.harnessClient.Collection("data")
	certsDoc := coll.Doc("2034-06-16:issuerAKI.certs")
	metaDoc := coll.Doc("2034-06-16:issuerAKI.meta")
	knownDoc := coll.Doc("2034-06-16:issuerAKI.known")

	_, err := certsDoc.Set(ctx, map[string]interface{}{
		"type":     "certs",
		kFieldData: []byte{0xDE, 0xAD},
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
	collection := h.harnessClient.Collection("data")
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
}

func Test_FirestoreStoreLoad(t *testing.T) {
	h := makeFirestoreHarness(t)
	defer h.cleanup()
	BackendTestStoreLoad(t, h.be)
}

func Test_FirestoreListFiles(t *testing.T) {
	h := makeFirestoreHarness(t)
	defer h.cleanup()
	BackendTestListFiles(t, h.be)
}

func Test_FirestoreLogState(t *testing.T) {
	h := makeFirestoreHarness(t)
	defer h.cleanup()
	BackendTestLogState(t, h.be)
}

func Test_FirestoreKnownCertificates(t *testing.T) {
	h := makeFirestoreHarness(t)
	defer h.cleanup()
	BackendTestKnownCertificates(t, h.be)
}

func Test_FirestoreIssuerMetadata(t *testing.T) {
	h := makeFirestoreHarness(t)
	defer h.cleanup()
	BackendTestIssuerMetadata(t, h.be)
}
