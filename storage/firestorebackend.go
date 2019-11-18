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
	"github.com/jpillora/backoff"
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
	client   *firestore.Client
	PageSize int
}

func NewFirestoreBackend(ctx context.Context, projectId string) (*FirestoreBackend, error) {
	client, err := firestore.NewClient(ctx, projectId)
	if err != nil {
		return nil, err
	}

	return &FirestoreBackend{
		client:   client,
		PageSize: 8 * 1024,
	}, nil
}

func (db *FirestoreBackend) Close() error {
	return db.client.Close()
}

func (db *FirestoreBackend) MarkDirty(id string) error {
	// is this needed?
	return nil
}

func (db *FirestoreBackend) StoreCertificatePEM(ctx context.Context, serial Serial, expDate ExpDate,
	issuer Issuer, b []byte) error {
	defer metrics.MeasureSince([]string{"StoreCertificatePEM"}, time.Now())
	id := filepath.Join("ct", expDate.ID(), "issuer", issuer.ID(), "certs", serial.ID())
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

func (db *FirestoreBackend) StoreKnownCertificateList(ctx context.Context, issuer Issuer,
	serials []Serial) error {
	panic("Not implemented")
}

func (db *FirestoreBackend) allocateExpDate(ctx context.Context, expDate ExpDate) error {
	doc := db.client.Doc(filepath.Join("ct", expDate.ID()))
	if doc == nil {
		return fmt.Errorf("Couldn't allocate document for exp date %s", expDate)
	}

	_, err := doc.Set(ctx, map[string]interface{}{
		kFieldType:    kTypeExpDate,
		kFieldExpDate: expDate.ID(),
	})
	return err
}

func (db *FirestoreBackend) allocateIssuerExpDate(ctx context.Context, expDate ExpDate,
	issuer Issuer) error {
	doc := db.client.Doc(filepath.Join("ct", expDate.ID(), "issuer", issuer.ID()))
	if doc == nil {
		return fmt.Errorf("Couldn't allocate document for exp date %s issuer %v", expDate, issuer)
	}

	_, err := doc.Set(ctx, map[string]interface{}{
		kFieldType:    kTypeMetadata,
		kFieldExpDate: expDate.ID(),
		kFieldIssuer:  issuer.ID(),
	})
	return err
}

func (db *FirestoreBackend) AllocateExpDateAndIssuer(ctx context.Context, expDate ExpDate,
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

func (db *FirestoreBackend) LoadCertificatePEM(ctx context.Context, serial Serial,
	expDate ExpDate, issuer Issuer) ([]byte, error) {
	startTime := time.Now()
	defer metrics.MeasureSince([]string{"LoadCertificatePEM"}, startTime)
	id := filepath.Join("ct", expDate.ID(), "issuer", issuer.ID(), "certs", serial.ID())
	doc := db.client.Doc(id)
	if doc == nil {
		return []byte{}, fmt.Errorf("Couldn't open Document %s. Remember that Firestore heirarchies must alterante Document/Collections.", id)
	}

	docsnap, err := doc.Get(ctx)
	if err != nil {
		return []byte{}, fmt.Errorf("Couldn't get document snapshot for %s: %v", id, err)
	}

	data, err := docsnap.DataAt(kFieldData)
	if err != nil {
		return []byte{}, fmt.Errorf("Couldn't get data field for %s: %v", id, err)
	}
	return data.([]byte), nil
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

func (db *FirestoreBackend) StreamExpirationDates(ctx context.Context,
	aNotBefore time.Time) (<-chan string, error) {
	c := make(chan string, 2048)
	go func() {
		defer metrics.MeasureSince([]string{"StreamExpirationDates"}, time.Now())
		defer close(c)

		aNotBefore = time.Date(aNotBefore.Year(), aNotBefore.Month(), aNotBefore.Day(),
			0, 0, 0, 0, time.UTC)

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

			t, err := time.Parse(kExpirationFormat, doc.Ref.ID)
			if err == nil && !t.Before(aNotBefore) {
				c <- doc.Ref.ID
			}

			metrics.MeasureSince([]string{"StreamExpirationDates-Next"}, cycleTime)
		}
	}()

	return c, nil
}

func (db *FirestoreBackend) ListExpirationDates(ctx context.Context,
	aNotBefore time.Time) ([]ExpDate, error) {
	expDates := []ExpDate{}
	dateChan, err := db.StreamExpirationDates(ctx, aNotBefore)
	if err != nil {
		return expDates, err
	}

	for expDateStr := range dateChan {
		expDate, err := NewExpDate(expDateStr)
		if err != nil {
			return expDates, err
		}
		expDates = append(expDates, expDate)
	}
	return expDates, nil
}

func (db *FirestoreBackend) StreamIssuersForExpirationDate(ctx context.Context,
	expDate ExpDate) (<-chan Issuer, error) {
	c := make(chan Issuer, 2048)

	go func() {
		defer metrics.MeasureSince([]string{"StreamIssuersForExpirationDate"}, time.Now())
		defer close(c)

		id := filepath.Join("ct", expDate.ID(), "issuer")
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

			name, err := doc.DataAt(kFieldIssuer)
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
	expDate ExpDate) ([]Issuer, error) {
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

func processSerialDocumentQuery(ctx context.Context, expDate ExpDate, issuer Issuer, q firestore.Query,
	quitChan <-chan struct{}, c chan<- UniqueCertIdentifier) (error, int, *firestore.DocumentSnapshot) {
	defer metrics.MeasureSince([]string{"StreamSerialsForExpirationDateAndIssuer-Window"}, time.Now())
	var count int
	var lastRef *firestore.DocumentSnapshot

	iter := q.Documents(ctx)
	for {
		select {
		case <-quitChan:
			return nil, count, lastRef
		default:
		}

		cycleTime := time.Now()

		doc, err := iter.Next()
		if err == iterator.Done {
			return nil, count, lastRef
		}
		if err != nil {
			return err, count, lastRef
		}
		if doc == nil {
			return fmt.Errorf("nil document returned"), count, nil
		}

		serialObj, err := NewSerialFromIDString(doc.Ref.ID)
		if err != nil {
			glog.Warningf("Invalid ID string for expDate=%s issuer=%s: %v", expDate, issuer.ID(), doc.Ref.ID)
			continue
		}

		c <- UniqueCertIdentifier{
			ExpDate:   expDate,
			Issuer:    issuer,
			SerialNum: serialObj,
		}

		lastRef = doc
		metrics.MeasureSince([]string{"StreamSerialsForExpirationDateAndIssuer-Next"}, cycleTime)
		count += 1
	}
}

func (db *FirestoreBackend) StreamSerialsForExpirationDateAndIssuer(ctx context.Context,
	expDate ExpDate, issuer Issuer, quitChan <-chan struct{},
	serialChan chan<- UniqueCertIdentifier) error {
	b := &backoff.Backoff{
		Jitter: true,
		Min:    125 * time.Millisecond,
		Max:    5 * time.Minute,
	}

	totalTime := time.Now()
	defer metrics.MeasureSince([]string{"StreamSerialsForExpirationDateAndIssuer"}, totalTime)

	id := filepath.Join("ct", expDate.ID(), "issuer", issuer.ID(), "certs")

	var offset int
	var lastRef *firestore.DocumentSnapshot
	for {
		select {
		case <-quitChan:
			return nil
		default:
		}

		subCtx, subCancel := context.WithTimeout(ctx, 5*time.Minute)

		query := db.client.Collection(id).Where(kFieldType, "==", kTypePEM).Limit(db.PageSize)
		if lastRef != nil {
			query = query.StartAfter(lastRef)
		}
		err, count, finalRef := processSerialDocumentQuery(subCtx, expDate, issuer, query, quitChan,
			serialChan)
		lastRef = finalRef
		offset += count

		subCancel()

		if err != nil {
			overlayErr := fmt.Errorf("(%s/%s) (total time: %s) (count=%d) (offset=%d) err=%s",
				expDate, issuer.ID(), time.Since(totalTime), count, offset, err)

			if ctx.Err() != nil {
				glog.Fatalf("StreamSerialsForExpirationDateAndIssuer iter.Next fatal top-level context "+
					"failure, received %d/%d records. (ctx.Err=%v) %s", count, db.PageSize, ctx.Err(),
					overlayErr)
			} else if status.Code(err) == codes.Unavailable ||
				status.Code(err) == codes.DeadlineExceeded ||
				strings.Contains(err.Error(), "context deadline exceeded") {
				d := b.Duration()
				if d > time.Minute {
					glog.Warningf("StreamSerialsForExpirationDateAndIssuer iter.Next Firestore unavailable, "+
						"received %d/%d records. Retrying in %s: %s", count, db.PageSize, d,
						overlayErr)
				}
				time.Sleep(d)
				continue
			} else if status.Code(err) == codes.OutOfRange {
				return fmt.Errorf("StreamSerialsForExpirationDateAndIssuer iter.Next out of range. %s",
					overlayErr)
			} else if status.Code(err) == codes.Canceled {
				glog.Infof("StreamSerialsForExpirationDateAndIssuer canceled: %v", overlayErr)
				return nil
			} else {
				glog.Fatalf("StreamSerialsForExpirationDateAndIssuer iter.Next unexpected code %s aborting: %v",
					status.Code(err), overlayErr)
				return nil
			}
		}

		b.Reset()

		if count == 0 {
			return nil
		}
	}
}

func (db *FirestoreBackend) ListSerialsForExpirationDateAndIssuer(ctx context.Context,
	expDate ExpDate, issuer Issuer) ([]Serial, error) {
	serials := []Serial{}
	serialChan := make(chan UniqueCertIdentifier, 1*1024*1024)
	quitChan := make(chan struct{})

	err := db.StreamSerialsForExpirationDateAndIssuer(ctx, expDate, issuer, quitChan, serialChan)
	if err != nil {
		return serials, err
	}
	close(serialChan)

	for tuple := range serialChan {
		serials = append(serials, tuple.SerialNum)
	}

	return serials, nil
}
