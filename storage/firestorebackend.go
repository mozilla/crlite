package storage

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"path/filepath"
	"time"

	"cloud.google.com/go/firestore"
	"github.com/golang/glog"
	"google.golang.org/api/iterator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

//
// logs
//     /<url>
// ct
//     /<expDate>
//                /issuer
//                        /<issuer>
//                                 /certs
//                                        /<spki>
//                                 /known
//                                        /serials

const (
	kFieldType    = "type"
	kFieldData    = "data"
	kFieldExpDate = "expDate"
	kFieldIssuer  = "issuer"
	kFieldURL     = "url"
	kTypePEM      = "PEM"
	kTypeSerials  = "Serials"
	kTypeLogState = "LogState"
	kTypeExpDate  = "ExpDate"
	kTypeMetadata = "Metadata"
)

type FirestoreBackend struct {
	ctx    context.Context
	client *firestore.Client
}

func NewFirestoreBackend(ctx context.Context, projectId string) (*FirestoreBackend, error) {
	client, err := firestore.NewClient(ctx, projectId)
	if err != nil {
		return nil, err
	}

	return &FirestoreBackend{ctx, client}, nil
}

func (db *FirestoreBackend) Close() error {
	return db.client.Close()
}

func (db *FirestoreBackend) MarkDirty(id string) error {
	// is this needed?
	return nil
}

func (db *FirestoreBackend) StoreCertificatePEM(spki SPKI, expDate string, issuer string, b []byte) error {
	if len(expDate) == 0 || len(issuer) == 0 {
		panic(fmt.Sprintf("StoreCertificatePEM invalid arguments: expDate [%+v] issuer [%+v]", expDate, issuer))
	}
	id := filepath.Join("ct", expDate, "issuer", issuer, "certs", spki.ID())
	doc := db.client.Doc(id)
	if doc == nil {
		return fmt.Errorf("Couldn't open Document %s. Remember that Firestore heirarchies must alterante Document/Collections.", id)
	}

	_, err := doc.Set(db.ctx, map[string]interface{}{
		kFieldType: kTypePEM,
		kFieldData: b,
	})
	return err
}

func logNameToId(logURL string) string {
	digest := sha256.Sum256([]byte(logURL))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func (db *FirestoreBackend) StoreLogState(logURL string, log *CertificateLog) error {
	id := filepath.Join("logs", logNameToId(logURL))
	doc := db.client.Doc(id)
	if doc == nil {
		return fmt.Errorf("Couldn't open Document %s. Remember that Firestore heirarchies must alterante Document/Collections.", id)
	}

	_, err := doc.Set(db.ctx, map[string]interface{}{
		kFieldType: kTypeLogState,
		kFieldURL:  logURL,
		kFieldData: log,
	})
	return err
}

func (db *FirestoreBackend) allocateExpDate(expDate string) error {
	doc := db.client.Doc(filepath.Join("ct", expDate))
	if doc == nil {
		return fmt.Errorf("Couldn't allocate document for exp date %s", expDate)
	}

	_, err := doc.Set(db.ctx, map[string]interface{}{
		kFieldType:    kTypeExpDate,
		kFieldExpDate: expDate,
	})
	return err
}

func (db *FirestoreBackend) StoreIssuerMetadata(expDate string, issuer string, data *Metadata) error {
	// This wastes writes, but not as much as if we did it on StorePEM.
	err := db.allocateExpDate(expDate)
	if err != nil {
		return err
	}

	id := filepath.Join("ct", expDate, "issuer", issuer)
	doc := db.client.Doc(id)
	if doc == nil {
		return fmt.Errorf("Couldn't open Document %s. Remember that Firestore heirarchies must alterante Document/Collections.", id)
	}

	_, err = doc.Set(db.ctx, map[string]interface{}{
		kFieldType:    kTypeMetadata,
		kFieldExpDate: expDate,
		kFieldIssuer:  issuer,
		kFieldData:    data,
	})
	return err
}

func (db *FirestoreBackend) StoreIssuerKnownSerials(expDate string, issuer string, serials []*big.Int) error {
	id := filepath.Join("ct", expDate, "issuer", issuer, "known", "serials")
	doc := db.client.Doc(id)
	if doc == nil {
		return fmt.Errorf("Couldn't open Document %s. Remember that Firestore heirarchies must alterante Document/Collections.", id)
	}

	_, err := doc.Set(db.ctx, map[string]interface{}{
		kFieldType:    kTypeSerials,
		kFieldExpDate: expDate,
		kFieldIssuer:  issuer,
		kFieldData:    serials,
	})
	return err
}

func (db *FirestoreBackend) LoadCertificatePEM(spki SPKI, expDate string, issuer string) ([]byte, error) {
	id := filepath.Join("ct", expDate, "issuer", issuer, "certs", spki.ID())
	doc := db.client.Doc(id)
	if doc == nil {
		return []byte{}, fmt.Errorf("Couldn't open Document %s. Remember that Firestore heirarchies must alterante Document/Collections.", id)
	}

	docsnap, err := doc.Get(db.ctx)
	if err != nil {
		return []byte{}, err
	}

	data, err := docsnap.DataAt(kFieldData)
	return data.([]byte), err
}

func (db *FirestoreBackend) LoadLogState(logURL string) (*CertificateLog, error) {
	id := filepath.Join("logs", logNameToId(logURL))
	doc := db.client.Doc(id)
	if doc == nil {
		return nil, fmt.Errorf("Couldn't open Document %s. Remember that Firestore heirarchies must alterante Document/Collections.", id)
	}

	docsnap, err := doc.Get(db.ctx)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			// The default state is a new log
			obj := &CertificateLog{
				URL: logURL,
			}
			glog.Warningf("Allocating brand new log for %s: %v", logURL, obj)
			return obj, nil
		}
		return nil, err
	}

	data, err := docsnap.DataAt(kFieldData)
	return data.(*CertificateLog), err
}

func (db *FirestoreBackend) LoadIssuerMetadata(expDate string, issuer string) (*Metadata, error) {
	id := filepath.Join("ct", expDate, "issuer", issuer)
	doc := db.client.Doc(id)
	if doc == nil {
		return nil, fmt.Errorf("Couldn't open Document %s. Remember that Firestore heirarchies must alterante Document/Collections.", id)
	}

	docsnap, err := doc.Get(db.ctx)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			// The default state is fresh Metadata
			obj := &Metadata{
				Crls:      []*string{},
				IssuerDNs: []*string{},
			}
			return obj, nil
		}
		return nil, err
	}

	data, err := docsnap.DataAt(kFieldData)
	return data.(*Metadata), err
}

func (db *FirestoreBackend) LoadIssuerKnownSerials(expDate string, issuer string) ([]*big.Int, error) {
	id := filepath.Join("ct", expDate, "issuer", issuer, "known", "serials")
	doc := db.client.Doc(id)
	if doc == nil {
		return nil, fmt.Errorf("Couldn't open Document %s. Remember that Firestore heirarchies must alterante Document/Collections.", id)
	}

	docsnap, err := doc.Get(db.ctx)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			// The default state is a new serials list
			return []*big.Int{}, nil
		}
		return nil, err
	}

	data, err := docsnap.DataAt(kFieldData)
	return data.([]*big.Int), err
}

func (db *FirestoreBackend) ListExpirationDates(aNotBefore time.Time) ([]string, error) {
	expDates := []string{}
	iter := db.client.Collection("ct").Where(kFieldType, "==", kTypeExpDate).Select().Documents(db.ctx)

	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}

		if err != nil || doc == nil {
			glog.Warningf("ListExpirationDates iter.Next err %+v\n", err)
			return []string{}, err
		}

		expDates = append(expDates, doc.Ref.ID)
	}

	return expDates, nil
}

func (db *FirestoreBackend) ListIssuersForExpirationDate(expDate string) ([]string, error) {
	issuers := []string{}

	id := filepath.Join("ct", expDate, "issuer")
	iter := db.client.Collection(id).Where(kFieldType, "==", kTypeMetadata).
		Documents(db.ctx)
	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}

		if err != nil || doc == nil {
			glog.Warningf("ListIssuersForExpirationDate iter.Next err %+v\n", err)
			return []string{}, err
		}

		name, err := doc.DataAt(kFieldIssuer)
		if err != nil {
			return []string{}, err
		}

		issuers = append(issuers, name.(string))
	}

	return issuers, nil
}
