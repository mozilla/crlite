package types

import (
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/google/certificate-transparency-go/x509"
	"net/url"
	"strings"
	"time"
)

const (
	kExpirationFormat         = "2006-01-02"
	kExpirationFormatWithHour = "2006-01-02-15"
)

/* The CTLogMetadata struct contains the information that we receive
 * `ct-logs` Remote Settings collection. */
type CTLogMetadata struct {
	CRLiteEnrolled bool   `json:"crlite_enrolled"`
	Description    string `json:"description"`
	Key            string `json:"key"`
	LogID          string `json:"logID"`
	MMD            int    `json:"mmd"`
	URL            string `json:"url"`
}

func (o *CTLogMetadata) MetricKey() string {
	metricKey := o.URL
	metricKey = strings.TrimPrefix(metricKey, "https://")
	metricKey = strings.TrimSuffix(metricKey, "/")
	metricKey = strings.ReplaceAll(metricKey, "/", ".")
	return metricKey
}

/* The CTLogState struct contains information necessary to describe a filter's
 * coverage of a CT log. */
type CTLogState struct {
	LogID          string    `db:"logID"`          // The log's RFC 6962 LogID
	MMD            uint64    `db:"mmd"`            // The log's maximum merge delay in seconds
	ShortURL       string    `db:"url"`            // URL to the log
	MinEntry       uint64    `db:"minEntry"`       // The smallest index we've downloaded
	MaxEntry       uint64    `db:"maxEntry"`       // The largest index we've downloaded
	MinTimestamp   uint64    `db:"minTimestamp"`   // Unix timestamp of the earliest entry we've downloaded
	MaxTimestamp   uint64    `db:"maxTimestamp"`   // Unix timestamp of the most recent entry we've downloaded
	LastUpdateTime time.Time `db:"lastUpdateTime"` // Date when we completed the last update
}

func (o *CTLogState) String() string {
	return fmt.Sprintf("[%s] MinEntry=%d, MaxEntry=%d, MaxTimestamp=%d, LastUpdateTime=%s",
		o.ShortURL, o.MinEntry, o.MaxEntry, o.MaxTimestamp, o.LastUpdateTime)
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
	return json.Marshal(o.ID())
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

func (s Serial) String() string {
	return s.HexString()
}

func (s Serial) BinaryString() string {
	return string(s.serial)
}

func (s Serial) HexString() string {
	return hex.EncodeToString(s.serial)
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

type IssuerCrlMap map[string]map[string]bool

func (self IssuerCrlMap) Merge(other IssuerCrlMap) {
	for issuer, crls := range other {
		selfCrls, pres := self[issuer]
		if !pres {
			selfCrls = make(map[string]bool)
		}
		for crl, _ := range crls {
			selfCrls[crl] = true
		}
		self[issuer] = selfCrls
	}
}

type IssuerCrlUrls struct {
	Issuer Issuer
	Urls   []url.URL
}

type UrlPath struct {
	Url  url.URL
	Path string
}

type IssuerCrlUrlPaths struct {
	Issuer      Issuer
	IssuerDN    string
	CrlUrlPaths []UrlPath
}

type TBSCertificateListWithRawSerials struct {
	Raw                 asn1.RawContent
	Version             int `asn1:"optional,default:0"`
	Signature           asn1.RawValue
	Issuer              asn1.RawValue
	ThisUpdate          time.Time
	NextUpdate          time.Time                         `asn1:"optional"`
	RevokedCertificates []RevokedCertificateWithRawSerial `asn1:"optional"`
}

type RevokedCertificateWithRawSerial struct {
	Raw            asn1.RawContent
	SerialNumber   asn1.RawValue
	RevocationTime time.Time
}

func DecodeRawTBSCertList(data []byte) (*TBSCertificateListWithRawSerials, error) {
	var tbsCertList TBSCertificateListWithRawSerials
	_, err := asn1.Unmarshal(data, &tbsCertList)
	return &tbsCertList, err
}

func NewSerialFromBytes(b []byte) Serial {
	obj := Serial{
		serial: b,
	}
	return obj
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

func NewSerialFromHex(s string) Serial {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return Serial{
		serial: b,
	}
}

func NewSerialFromBinaryString(s string) (Serial, error) {
	bytes := []byte(s)
	return NewSerialFromBytes(bytes), nil
}

type IssuerAndDate struct {
	ExpDate ExpDate
	Issuer  Issuer
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

type IssuerDate struct {
	Issuer   Issuer
	ExpDates []ExpDate
}
