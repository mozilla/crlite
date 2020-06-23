package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/google/certificate-transparency-go/x509"
)

const (
	kExpirationFormat         = "2006-01-02"
	kExpirationFormatWithHour = "2006-01-02-15"
)

type CertificateLog struct {
	ShortURL       string    `db:"url"`            // URL to the log
	MaxEntry       int64     `db:"maxEntry"`       // The most recent entryID logged
	LastEntryTime  time.Time `db:"lastEntryTime"`  // Date of the most recently logged entry
	LastUpdateTime time.Time `db:"lastUpdateTime"` // Date when we completed the last update
}

func (o *CertificateLog) String() string {
	return fmt.Sprintf("[%s] MaxEntry=%d, LastEntryTime=%s LastUpdateTime=%s", o.ShortURL, o.MaxEntry, o.LastEntryTime, o.LastUpdateTime)
}

func CertificateLogIDFromShortURL(shortURL string) string {
	return base64.URLEncoding.EncodeToString([]byte(shortURL))
}

func (o *CertificateLog) ID() string {
	return CertificateLogIDFromShortURL(o.ShortURL)
}

type DocumentType int

type StorageBackend interface {
	MarkDirty(id string) error

	StoreCertificatePEM(ctx context.Context, serial Serial, expDate ExpDate,
		issuer Issuer, b []byte) error
	StoreLogState(ctx context.Context, log *CertificateLog) error
	StoreKnownCertificateList(ctx context.Context, issuer Issuer,
		serials []Serial) error

	LoadCertificatePEM(ctx context.Context, serial Serial, expDate ExpDate,
		issuer Issuer) ([]byte, error)
	LoadLogState(ctx context.Context, logURL string) (*CertificateLog, error)

	AllocateExpDateAndIssuer(ctx context.Context, expDate ExpDate, issuer Issuer) error

	ListExpirationDates(ctx context.Context, aNotBefore time.Time) ([]ExpDate, error)
	ListIssuersForExpirationDate(ctx context.Context, expDate ExpDate) ([]Issuer, error)

	ListSerialsForExpirationDateAndIssuer(ctx context.Context, expDate ExpDate,
		issuer Issuer) ([]Serial, error)
	StreamSerialsForExpirationDateAndIssuer(ctx context.Context, expDate ExpDate,
		issuer Issuer, quitChan <-chan struct{}, stream chan<- UniqueCertIdentifier) error
}

type CertDatabase interface {
	Cleanup() error
	SaveLogState(aLogObj *CertificateLog) error
	GetLogState(url *url.URL) (*CertificateLog, error)
	GetAllLogStates() []*CertificateLog
	Store(aCert *x509.Certificate, aIssuer *x509.Certificate, aURL string,
		aEntryId int64) error
	ListExpirationDates(aNotBefore time.Time) ([]ExpDate, error)
	ListIssuersForExpirationDate(expDate ExpDate) ([]Issuer, error)
	GetKnownCertificates(aExpDate ExpDate, aIssuer Issuer) *KnownCertificates
	GetIssuerMetadata(aIssuer Issuer) *IssuerMetadata
	GetIssuerAndDatesFromCache() ([]IssuerDate, error)
}

type RemoteCache interface {
	Exists(key string) (bool, error)
	SetInsert(key string, aEntry string) (bool, error)
	SetRemove(key string, entry string) (bool, error)
	SetContains(key string, aEntry string) (bool, error)
	SetList(key string) ([]string, error)
	SetToChan(key string, c chan<- string) error
	SetCardinality(key string) (int, error)
	ExpireAt(key string, aExpTime time.Time) error
	ExpireIn(key string, aDur time.Duration) error
	Queue(key string, identifier string) (int64, error)
	Pop(key string) (string, error)
	QueueLength(key string) (int64, error)
	BlockingPopCopy(key string, dest string, timeout time.Duration) (string, error)
	ListRemove(key string, value string) error
	TrySet(k string, v string, life time.Duration) (string, error)
	KeysToChan(pattern string, c chan<- string) error
	StoreLogState(aLogObj *CertificateLog) error
	LoadLogState(aLogUrl string) (*CertificateLog, error)
	GetAllLogStates() ([]*CertificateLog, error)
}

type Issuer struct {
	id   *string
	spki SPKI
}

func NewIssuer(aCert *x509.Certificate) Issuer {
	obj := Issuer{
		id:   nil,
		spki: SPKI{aCert.RawSubjectPublicKeyInfo},
	}
	return obj
}

func NewIssuerFromString(aStr string) Issuer {
	obj := Issuer{
		id: &aStr,
	}
	return obj
}

func (o *Issuer) ID() string {
	if o.id == nil {
		encodedDigest := o.spki.Sha256DigestURLEncodedBase64()
		o.id = &encodedDigest
	}
	return *o.id
}

func (o *Issuer) MarshalJSON() ([]byte, error) {
	if o.id == nil {
		_ = o.ID()
	}
	return json.Marshal(o.id)
}

func (o *Issuer) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &o.id)
}

type SPKI struct {
	spki []byte
}

func (o SPKI) ID() string {
	return base64.URLEncoding.EncodeToString(o.spki)
}

func (o SPKI) String() string {
	return hex.EncodeToString(o.spki)
}

func (o SPKI) Sha256DigestURLEncodedBase64() string {
	binaryDigest := sha256.Sum256(o.spki)
	encodedDigest := base64.URLEncoding.EncodeToString(binaryDigest[:])
	return encodedDigest
}

type Serial struct {
	serial []byte
}

type tbsCertWithRawSerial struct {
	Raw          asn1.RawContent
	Version      asn1.RawValue `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber asn1.RawValue
}

func NewSerial(aCert *x509.Certificate) Serial {
	var tbsCert tbsCertWithRawSerial
	_, err := asn1.Unmarshal(aCert.RawTBSCertificate, &tbsCert)
	if err != nil {
		panic(err)
	}
	return NewSerialFromBytes(tbsCert.SerialNumber.Bytes)
}

func NewSerialFromBytes(b []byte) Serial {
	obj := Serial{
		serial: b,
	}
	return obj
}

func NewSerialFromHex(s string) Serial {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return Serial{
		serial: b,
	}
}

func NewSerialFromIDString(s string) (Serial, error) {
	bytes, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		return Serial{}, err
	}
	return NewSerialFromBytes(bytes), nil
}

func NewSerialFromBinaryString(s string) (Serial, error) {
	bytes := []byte(s)
	return NewSerialFromBytes(bytes), nil
}

func (s Serial) ID() string {
	return base64.URLEncoding.EncodeToString(s.serial)
}

func (s Serial) String() string {
	return s.HexString()
}

func (s Serial) BinaryString() string {
	return string(s.serial)
}

func (s Serial) HexString() string {
	return hex.EncodeToString(s.serial)
}

func (s Serial) Cmp(o Serial) int {
	return bytes.Compare(s.serial, o.serial)
}

func (s Serial) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.HexString())
}

func (s *Serial) UnmarshalJSON(data []byte) error {
	if data[0] != '"' || data[len(data)-1] != '"' {
		return fmt.Errorf("Expected surrounding quotes")
	}
	b, err := hex.DecodeString(string(data[1 : len(data)-1]))
	s.serial = b
	return err
}

func (s Serial) MarshalBinary() ([]byte, error) {
	return s.MarshalJSON()
}

func (s *Serial) UnmarshalBinary(data []byte) error {
	return s.UnmarshalJSON(data)
}

func (s *Serial) AsBigInt() *big.Int {
	serialBigInt := big.NewInt(0)
	serialBigInt.SetBytes(s.serial)
	return serialBigInt
}

type SerialList []Serial

func (sl SerialList) Len() int {
	return len(sl)
}

func (sl SerialList) Less(i, j int) bool {
	return sl[i].Cmp(sl[j]) < 0
}

func (sl SerialList) Swap(i, j int) {
	tmp := sl[i]
	sl[i] = sl[j]
	sl[j] = tmp
}

type UniqueCertIdentifier struct {
	ExpDate   ExpDate
	Issuer    Issuer
	SerialNum Serial
}

func ParseUniqueCertIdentifier(s string) (UniqueCertIdentifier, error) {
	parts := strings.Split(s, "::")
	if len(parts) != 3 {
		return UniqueCertIdentifier{}, fmt.Errorf("Expected 3 parts, got %d", len(parts))
	}

	e, err := NewExpDate(parts[0])
	if err != nil {
		return UniqueCertIdentifier{}, err
	}

	i := NewIssuerFromString(parts[1])

	n, err := NewSerialFromIDString(parts[2])
	if err != nil {
		return UniqueCertIdentifier{}, err
	}

	return UniqueCertIdentifier{
		ExpDate:   e,
		Issuer:    i,
		SerialNum: n,
	}, nil
}

func (uci UniqueCertIdentifier) String() string {
	return fmt.Sprintf("%s::%s::%s", uci.ExpDate.ID(), uci.Issuer.ID(), uci.SerialNum.ID())
}

type IssuerAndDate struct {
	ExpDate ExpDate
	Issuer  Issuer
}

func ParseIssuerAndDate(s string) (IssuerAndDate, error) {
	parts := strings.Split(s, "/")
	if len(parts) != 2 {
		return IssuerAndDate{},
			fmt.Errorf("Unexpected number of parts: %d from %s", len(parts), s)
	}
	expDate, err := NewExpDate(parts[0])
	if err != nil {
		return IssuerAndDate{}, err
	}
	return IssuerAndDate{
		ExpDate: expDate,
		Issuer:  NewIssuerFromString(parts[1]),
	}, nil
}

func (t *IssuerAndDate) String() string {
	return fmt.Sprintf("%s/%s", t.ExpDate.ID(), t.Issuer.ID())
}

type ExpDate struct {
	date           time.Time
	lastGood       time.Time
	hourResolution bool
}

func NewExpDateFromTime(t time.Time) ExpDate {
	truncTime := t.Truncate(time.Hour)
	return ExpDate{
		date:           truncTime,
		lastGood:       truncTime.Add(-1 * time.Millisecond),
		hourResolution: true,
	}
}

func NewExpDate(s string) (ExpDate, error) {
	if len(s) > 10 {
		t, err := time.Parse(kExpirationFormatWithHour, s)
		if err == nil {
			lastGood := t.Add(1 * time.Hour)
			lastGood = lastGood.Add(-1 * time.Millisecond)
			return ExpDate{t, lastGood, true}, nil
		}
	}

	t, err := time.Parse(kExpirationFormat, s)
	if err == nil {
		lastGood := t.Add(24 * time.Hour)
		lastGood = lastGood.Add(-1 * time.Millisecond)
		return ExpDate{t, lastGood, false}, nil
	}
	return ExpDate{}, err
}

func (e ExpDate) IsExpiredAt(t time.Time) bool {
	return e.lastGood.Before(t)
}

func (e ExpDate) ExpireTime() time.Time {
	return e.date
}

func (e ExpDate) String() string {
	return e.ID()
}

func (e ExpDate) ID() string {
	if e.hourResolution {
		return e.date.Format(kExpirationFormatWithHour)
	}
	return e.date.Format(kExpirationFormat)
}

type ExpDateList []ExpDate

func (sl ExpDateList) Len() int {
	return len(sl)
}

func (sl ExpDateList) Less(i, j int) bool {
	return sl[i].date.Before(sl[j].date)
}

func (sl ExpDateList) Swap(i, j int) {
	tmp := sl[i]
	sl[i] = sl[j]
	sl[j] = tmp
}

type IssuerDate struct {
	Issuer   Issuer
	ExpDates []ExpDate
}
