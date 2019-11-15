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
	"time"

	"github.com/google/certificate-transparency-go/x509"
)

const (
	kExpirationFormat = "2006-01-02"
)

type CertificateLog struct {
	ShortURL      string    `db:"url"`           // URL to the log
	MaxEntry      int64     `db:"maxEntry"`      // The most recent entryID logged
	LastEntryTime time.Time `db:"lastEntryTime"` // Date when we completed the last update
}

func (o *CertificateLog) String() string {
	return fmt.Sprintf("[%s] MaxEntry=%d, LastEntryTime=%s", o.ShortURL, o.MaxEntry, o.LastEntryTime)
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

	StoreCertificatePEM(ctx context.Context, serial Serial, expDate string,
		issuer Issuer, b []byte) error
	StoreLogState(ctx context.Context, log *CertificateLog) error
	StoreKnownCertificateList(ctx context.Context, issuer Issuer,
		serials []Serial) error

	LoadCertificatePEM(ctx context.Context, serial Serial, expDate string,
		issuer Issuer) ([]byte, error)
	LoadLogState(ctx context.Context, logURL string) (*CertificateLog, error)

	AllocateExpDateAndIssuer(ctx context.Context, expDate string, issuer Issuer) error

	ListExpirationDates(ctx context.Context, aNotBefore time.Time) ([]string, error)
	ListIssuersForExpirationDate(ctx context.Context, expDate string) ([]Issuer, error)

	ListSerialsForExpirationDateAndIssuer(ctx context.Context, expDate string,
		issuer Issuer) ([]Serial, error)
	StreamSerialsForExpirationDateAndIssuer(ctx context.Context, expDate string,
		issuer Issuer, quitChan <-chan struct{}, stream chan<- UniqueCertIdentifier) error
}

type CertDatabase interface {
	Cleanup() error
	SaveLogState(aLogObj *CertificateLog) error
	GetLogState(url *url.URL) (*CertificateLog, error)
	Store(aCert *x509.Certificate, aIssuer *x509.Certificate, aURL string,
		aEntryId int64) error
	ListExpirationDates(aNotBefore time.Time) ([]string, error)
	ListIssuersForExpirationDate(expDate string) ([]Issuer, error)
	GetKnownCertificates(aExpDate string, aIssuer Issuer) *KnownCertificates
	GetIssuerMetadata(aIssuer Issuer) *IssuerMetadata
}

type RemoteCache interface {
	Exists(key string) (bool, error)
	SetInsert(key string, aEntry string) (bool, error)
	SetContains(key string, aEntry string) (bool, error)
	SetList(key string) ([]string, error)
	ExpireAt(key string, aExpTime time.Time) error
	Queue(key string, identifier string) (int64, error)
	Pop(key string) (string, error)
	QueueLength(key string) (int64, error)
	Keys(pattern string) ([]string, error)
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
	ExpDate   string
	Issuer    Issuer
	SerialNum Serial
}
