package storage

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"time"

	"cloud.google.com/go/firestore"
	"github.com/golang/glog"
	// "github.com/golang/protobuf/ptypes/timestamp"
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
	kFieldType     = "type"
	kFieldData     = "data"
	kFieldExpDate  = "expDate"
	kFieldIssuer   = "issuer"
	kFieldURL      = "shortUrl"
	kFieldUnixTime = "unixTime"
	kTypePEM       = "PEM"
	kTypeLogState  = "LogState"
	kTypeExpDate   = "ExpDate"
	kTypeMetadata  = "Metadata"
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

func (db *FirestoreBackend) StoreCertificatePEM(serial Serial, expDate string, issuer Issuer, b []byte) error {
	if len(expDate) == 0 {
		panic(fmt.Sprintf("StoreCertificatePEM invalid arguments: expDate [%+v] issuer [%+v]", expDate, issuer))
	}
	id := filepath.Join("ct", expDate, "issuer", issuer.ID(), "certs", serial.ID())
	doc := db.client.Doc(id)
	if doc == nil {
		return fmt.Errorf("Couldn't open Document id=%s. Remember that Firestore heirarchies must alterante Document/Collections.", id)
	}

	_, err := doc.Create(db.ctx, map[string]interface{}{
		kFieldType: kTypePEM,
		kFieldData: b,
	})

	if err != nil && status.Code(err) == codes.AlreadyExists {
		glog.V(1).Infof("Attempted to write a colliding document id=%s len=%d", id, len(b))
		return nil
	}

	return err
}

func logNameToId(logURL string) string {
	digest := sha256.Sum256([]byte(logURL))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func (db *FirestoreBackend) StoreLogState(log *CertificateLog) error {
	id := filepath.Join("logs", logNameToId(log.ShortURL))
	doc := db.client.Doc(id)
	if doc == nil {
		return fmt.Errorf("Couldn't open Document %s. Remember that Firestore heirarchies must alterante Document/Collections.", id)
	}

	_, err := doc.Set(db.ctx, map[string]interface{}{
		kFieldType:     kTypeLogState,
		kFieldURL:      log.ShortURL,
		kFieldData:     log.MaxEntry,
		kFieldUnixTime: log.LastEntryTime.Unix(),
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

func (db *FirestoreBackend) allocateIssuerExpDate(expDate string, issuer Issuer) error {
	doc := db.client.Doc(filepath.Join("ct", expDate, "issuer", issuer.ID()))
	if doc == nil {
		return fmt.Errorf("Couldn't allocate document for exp date %s issuer %v", expDate, issuer)
	}

	_, err := doc.Set(db.ctx, map[string]interface{}{
		kFieldType:    kTypeMetadata,
		kFieldExpDate: expDate,
		kFieldIssuer:  issuer.ID(),
	})
	return err
}

func (db *FirestoreBackend) AllocateExpDateAndIssuer(expDate string, issuer Issuer) error {
	err := db.allocateExpDate(expDate)
	if err != nil {
		return err
	}
	return db.allocateIssuerExpDate(expDate, issuer)
}

func (db *FirestoreBackend) LoadCertificatePEM(serial Serial, expDate string, issuer Issuer) ([]byte, error) {
	id := filepath.Join("ct", expDate, "issuer", issuer.ID(), "certs", serial.ID())
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
				ShortURL: logURL,
			}
			glog.Warningf("Allocating brand new log for %s: %v", logURL, obj)
			return obj, nil
		}
		return nil, err
	}

	url, err := docsnap.DataAt(kFieldURL)
	if err != nil {
		return nil, err
	}
	maxEntry, err := docsnap.DataAt(kFieldData)
	if err != nil {
		return nil, err
	}
	timeSec, err := docsnap.DataAt(kFieldUnixTime)
	if err != nil {
		return nil, err
	}

	logObj := &CertificateLog{
		ShortURL:      url.(string),
		MaxEntry:      maxEntry.(int64),
		LastEntryTime: time.Unix(timeSec.(int64), 0),
	}
	return logObj, err
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

func (db *FirestoreBackend) ListIssuersForExpirationDate(expDate string) ([]Issuer, error) {
	issuers := []Issuer{}

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
			return []Issuer{}, err
		}

		name, err := doc.DataAt(kFieldIssuer)
		if err != nil {
			return []Issuer{}, err
		}

		issuerObj := NewIssuerFromString(name.(string))

		issuers = append(issuers, issuerObj)
	}

	return issuers, nil
}

func (db *FirestoreBackend) ListSerialsForExpirationDateAndIssuer(expDate string, issuer Issuer) ([]Serial, error) {
	serials := []Serial{}

	id := filepath.Join("ct", expDate, "issuer", issuer.ID(), "certs")
	iter := db.client.Collection(id).Where(kFieldType, "==", kTypePEM).
		Documents(db.ctx)
	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}

		if err != nil || doc == nil {
			glog.Warningf("ListIssuersForExpirationDate iter.Next err %+v\n", err)
			return []Serial{}, err
		}

		glog.Infof("%v", doc.Ref.ID)

		serialObj, err := NewSerialFromIDString(doc.Ref.ID)
		if err != nil {
			glog.Warningf("Invalid ID string for expDate=%s issuer=%s: %+v", expDate, issuer.ID(), doc.Ref.ID)
			continue
		}

		serials = append(serials, serialObj)
	}

	return serials, nil
}
