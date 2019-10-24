package storage

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"cloud.google.com/go/firestore"
	"github.com/armon/go-metrics"
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
	client *firestore.Client
}

func NewFirestoreBackend(ctx context.Context, projectId string) (*FirestoreBackend, error) {
	client, err := firestore.NewClient(ctx, projectId)
	if err != nil {
		return nil, err
	}

	return &FirestoreBackend{client}, nil
}

func (db *FirestoreBackend) Close() error {
	return db.client.Close()
}

func (db *FirestoreBackend) MarkDirty(id string) error {
	// is this needed?
	return nil
}

func (db *FirestoreBackend) StoreCertificatePEM(ctx context.Context, serial Serial, expDate string,
	issuer Issuer, b []byte) error {
	defer metrics.MeasureSince([]string{"StoreCertificatePEM"}, time.Now())
	if len(expDate) == 0 {
		panic(fmt.Sprintf("StoreCertificatePEM invalid arguments: expDate [%+v] issuer [%+v]", expDate, issuer))
	}
	id := filepath.Join("ct", expDate, "issuer", issuer.ID(), "certs", serial.ID())
	doc := db.client.Doc(id)
	if doc == nil {
		return fmt.Errorf("Couldn't open Document id=%s. Remember that Firestore heirarchies must alterante Document/Collections.", id)
	}

	_, err := doc.Create(ctx, map[string]interface{}{
		kFieldType: kTypePEM,
		kFieldData: b,
	})

	if err != nil && status.Code(err) == codes.AlreadyExists {
		glog.V(1).Infof("Attempted to write a colliding document id=%s len=%d", id, len(b))
		metrics.IncrCounter([]string{"StoreCertificatePEM", "collision"}, 1)
		return nil
	}

	metrics.IncrCounter([]string{"StoreCertificatePEM", "success"}, 1)
	return err
}

func logNameToId(logURL string) string {
	digest := sha256.Sum256([]byte(logURL))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func (db *FirestoreBackend) StoreLogState(ctx context.Context, log *CertificateLog) error {
	defer metrics.MeasureSince([]string{"StoreLogState"}, time.Now())
	id := filepath.Join("logs", logNameToId(log.ShortURL))
	doc := db.client.Doc(id)
	if doc == nil {
		return fmt.Errorf("Couldn't open Document %s. Remember that Firestore heirarchies must alterante Document/Collections.", id)
	}

	_, err := doc.Set(ctx, map[string]interface{}{
		kFieldType:     kTypeLogState,
		kFieldURL:      log.ShortURL,
		kFieldData:     log.MaxEntry,
		kFieldUnixTime: log.LastEntryTime.Unix(),
	})
	return err
}

func (db *FirestoreBackend) StoreKnownCertificateList(ctx context.Context, useType SerialUseType,
	issuer Issuer, serials []Serial) error {
	panic("Not implemented")
}

func (db *FirestoreBackend) allocateExpDate(ctx context.Context, expDate string) error {
	doc := db.client.Doc(filepath.Join("ct", expDate))
	if doc == nil {
		return fmt.Errorf("Couldn't allocate document for exp date %s", expDate)
	}

	_, err := doc.Set(ctx, map[string]interface{}{
		kFieldType:    kTypeExpDate,
		kFieldExpDate: expDate,
	})
	return err
}

func (db *FirestoreBackend) allocateIssuerExpDate(ctx context.Context, expDate string,
	issuer Issuer) error {
	doc := db.client.Doc(filepath.Join("ct", expDate, "issuer", issuer.ID()))
	if doc == nil {
		return fmt.Errorf("Couldn't allocate document for exp date %s issuer %v", expDate, issuer)
	}

	_, err := doc.Set(ctx, map[string]interface{}{
		kFieldType:    kTypeMetadata,
		kFieldExpDate: expDate,
		kFieldIssuer:  issuer.ID(),
	})
	return err
}

func (db *FirestoreBackend) AllocateExpDateAndIssuer(ctx context.Context, expDate string,
	issuer Issuer) error {
	defer metrics.MeasureSince([]string{"AllocateExpDateAndIssuer"}, time.Now())
	err := db.allocateExpDate(ctx, expDate)
	if err != nil {
		return fmt.Errorf("Could not allocateExpDate %s/%s: %v", expDate, issuer.ID(), err)
	}
	err = db.allocateIssuerExpDate(ctx, expDate, issuer)
	if err != nil {
		return fmt.Errorf("Could not allocateIssuerExpDate %s/%s: %v", expDate, issuer.ID(), err)
	}
	return nil
}

func dataAtWithRetry(docsnap *firestore.DocumentSnapshot, fieldName string,
	funcName string) (interface{}, error) {
	startTime := time.Now()
	defer metrics.MeasureSince([]string{"dataAtWithRetry", funcName}, startTime)

	for i := 0; i < 10; i++ {
		data, err := docsnap.DataAt(fieldName)
		if err != nil {
			if strings.Contains(err.Error(), "deadline exceeded") {
				glog.V(1).Infof("%s Deadline exceeded, retrying (total time=%s)",
					funcName, time.Since(startTime))
				metrics.IncrCounter([]string{funcName, "DeadlineExceeded"}, 1)
				metrics.AddSample([]string{funcName, "DeadlineExceededAtCycleTime"},
					float32(time.Since(startTime).Seconds()))
				continue // retry
			}
			return []byte{}, fmt.Errorf("%s Couldn't get data field for %s (elapsed=%s): %v",
				funcName, fieldName, time.Since(startTime), err)
		}
		return data, nil
	}
	return []byte{}, fmt.Errorf("%s failed all retries for data field %s (elapsed=%s)",
		funcName, fieldName, time.Since(startTime))
}

func (db *FirestoreBackend) LoadCertificatePEM(ctx context.Context, serial Serial,
	expDate string, issuer Issuer) ([]byte, error) {
	startTime := time.Now()
	defer metrics.MeasureSince([]string{"LoadCertificatePEM"}, startTime)
	id := filepath.Join("ct", expDate, "issuer", issuer.ID(), "certs", serial.ID())
	doc := db.client.Doc(id)
	if doc == nil {
		return []byte{}, fmt.Errorf("Couldn't open Document %s. Remember that Firestore heirarchies must alterante Document/Collections.", id)
	}

	docsnap, err := doc.Get(ctx)
	if err != nil {
		return []byte{}, fmt.Errorf("Couldn't get document snapshot for %s: %v", id, err)
	}

	data, err := dataAtWithRetry(docsnap, kFieldData, "LoadCertificatePEM")
	return data.([]byte), err
}

func (db *FirestoreBackend) LoadLogState(ctx context.Context,
	logURL string) (*CertificateLog, error) {
	defer metrics.MeasureSince([]string{"LoadLogState"}, time.Now())
	id := filepath.Join("logs", logNameToId(logURL))
	doc := db.client.Doc(id)
	if doc == nil {
		return nil, fmt.Errorf("Couldn't open Document %s. Remember that Firestore heirarchies must alterante Document/Collections.", id)
	}

	docsnap, err := doc.Get(ctx)
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

	url, err := dataAtWithRetry(docsnap, kFieldURL, "LoadLogState")
	if err != nil {
		return nil, err
	}
	maxEntry, err := dataAtWithRetry(docsnap, kFieldData, "LoadLogState")
	if err != nil {
		return nil, err
	}
	timeSec, err := dataAtWithRetry(docsnap, kFieldUnixTime, "LoadLogState")
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

func (db *FirestoreBackend) StreamExpirationDates(ctx context.Context,
	aNotBefore time.Time) (<-chan string, error) {
	c := make(chan string, 2048)
	go func() {
		defer metrics.MeasureSince([]string{"StreamExpirationDates"}, time.Now())
		defer close(c)

		iter := db.client.Collection("ct").Where(kFieldType, "==", kTypeExpDate).
			Select().Documents(ctx)

		for {
			cycleTime := time.Now()

			doc, err := iter.Next()
			if err == iterator.Done {
				return
			}

			if err != nil || doc == nil {
				glog.Warningf("StreamExpirationDates iter.Next err %v", err)
				return
			}

			c <- doc.Ref.ID
			metrics.MeasureSince([]string{"StreamExpirationDates-Next"}, cycleTime)
		}
	}()

	return c, nil
}

func (db *FirestoreBackend) ListExpirationDates(ctx context.Context,
	aNotBefore time.Time) ([]string, error) {
	defer metrics.MeasureSince([]string{"ListExpirationDates"}, time.Now())
	expDates := []string{}
	dateChan, err := db.StreamExpirationDates(ctx, aNotBefore)
	if err != nil {
		return expDates, err
	}

	for expDate := range dateChan {
		expDates = append(expDates, expDate)
	}
	return expDates, nil
}

func (db *FirestoreBackend) StreamIssuersForExpirationDate(ctx context.Context,
	expDate string) (<-chan Issuer, error) {
	c := make(chan Issuer, 2048)

	go func() {
		defer metrics.MeasureSince([]string{"StreamIssuersForExpirationDate"}, time.Now())
		defer close(c)

		id := filepath.Join("ct", expDate, "issuer")
		iter := db.client.Collection(id).Where(kFieldType, "==", kTypeMetadata).
			Documents(ctx)
		for {
			cycleTime := time.Now()

			doc, err := iter.Next()
			if err == iterator.Done {
				return
			}

			if err != nil || doc == nil {
				glog.Warningf("StreamIssuersForExpirationDate iter.Next err %v", err)
				return
			}

			name, err := dataAtWithRetry(doc, kFieldIssuer, "StreamIssuersForExpirationDate")
			if err != nil {
				glog.Warningf("Invalid issuer object: %+v :: %v", doc, err)
				continue
			}

			c <- NewIssuerFromString(name.(string))
			metrics.MeasureSince([]string{"StreamIssuersForExpirationDate-Next"}, cycleTime)
		}
	}()

	return c, nil
}

func (db *FirestoreBackend) ListIssuersForExpirationDate(ctx context.Context,
	expDate string) ([]Issuer, error) {
	defer metrics.MeasureSince([]string{"ListIssuersForExpirationDate"}, time.Now())
	issuers := []Issuer{}

	issuerChan, err := db.StreamIssuersForExpirationDate(ctx, expDate)
	if err != nil {
		return issuers, err
	}

	for issuer := range issuerChan {
		issuers = append(issuers, issuer)
	}
	return issuers, nil
}

func processSerialDocumentQuery(ctx context.Context, expDate string, issuer Issuer, q firestore.Query,
	c chan<- Serial) (error, int) {
	defer metrics.MeasureSince([]string{"StreamSerialsForExpirationDateAndIssuer-Window"}, time.Now())
	var count int
	iter := q.Documents(ctx)
	for {
		cycleTime := time.Now()

		doc, err := iter.Next()
		if err == iterator.Done {
			return nil, count
		}
		if err != nil {
			return err, count
		}
		if doc == nil {
			return fmt.Errorf("nil document returned"), count
		}

		serialObj, err := NewSerialFromIDString(doc.Ref.ID)
		if err != nil {
			glog.Warningf("Invalid ID string for expDate=%s issuer=%s: %v", expDate, issuer.ID(), doc.Ref.ID)
			continue
		}

		c <- serialObj
		metrics.MeasureSince([]string{"StreamSerialsForExpirationDateAndIssuer-Next"}, cycleTime)
		count += 1
	}
}

func (db *FirestoreBackend) StreamSerialsForExpirationDateAndIssuer(ctx context.Context,
	expDate string, issuer Issuer) (<-chan Serial, error) {
	c := make(chan Serial, 1*1024*1024)

	go func() {
		totalTime := time.Now()
		defer metrics.MeasureSince([]string{"StreamSerialsForExpirationDateAndIssuer"}, totalTime)
		defer close(c)
		id := filepath.Join("ct", expDate, "issuer", issuer.ID(), "certs")

		var offset int
		for {
			cycleTime := time.Now()
			query := db.client.Collection(id).Where(kFieldType, "==", kTypePEM).Limit(4096).Offset(offset)
			err, count := processSerialDocumentQuery(ctx, expDate, issuer, query, c)
			offset += count

			if err != nil {
				if strings.Contains(err.Error(), "deadline exceeded") {
					glog.V(1).Infof("StreamSerialsForExpirationDateAndIssuer Deadline exceeded, retrying (cycle time=%s) (total time=%s) (offset=%d) (count=%d) (queue len=%d)",
						time.Since(cycleTime), time.Since(totalTime), offset, count, len(c))
					metrics.IncrCounter([]string{"StreamSerialsForExpirationDateAndIssuer", "DeadlineExceeded"}, 1)
					metrics.AddSample([]string{"StreamSerialsForExpirationDateAndIssuer", "DeadlineExceededAtPosition"},
						float32(count))
					metrics.AddSample([]string{"StreamSerialsForExpirationDateAndIssuer", "DeadlineExceededAtCycleTime"},
						float32(time.Since(cycleTime).Seconds()))
					metrics.AddSample([]string{"StreamSerialsForExpirationDateAndIssuer", "DeadlineExceededQueueLength"},
						float32(len(c)))
					continue
				}

				glog.Errorf("StreamSerialsForExpirationDateAndIssuer iter.Next (total time: %s) (offset=%d) (queue len=%d) err %v",
					time.Since(totalTime), offset, len(c), err)
				return
			}

			if count == 0 {
				metrics.AddSample([]string{"StreamSerialsForExpirationDateAndIssuer", "TotalSerials"},
					float32(offset))
				return
			}
		}
	}()

	return c, nil
}

func (db *FirestoreBackend) ListSerialsForExpirationDateAndIssuer(ctx context.Context,
	expDate string, issuer Issuer) ([]Serial, error) {
	defer metrics.MeasureSince([]string{"ListSerialsForExpirationDateAndIssuer"}, time.Now())
	serials := []Serial{}

	serialChan, err := db.StreamSerialsForExpirationDateAndIssuer(ctx, expDate, issuer)
	if err != nil {
		return serials, err
	}

	for serial := range serialChan {
		serials = append(serials, serial)
	}

	return serials, nil
}
