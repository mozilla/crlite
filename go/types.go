package types

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/google/certificate-transparency-go/x509"
	"math/big"
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

type IssuerRevocations struct {
	Issuer         Issuer
	RevokedSerials []Serial
}

func (self IssuerRevocations) Merge(other IssuerRevocations) {
	panic("Not implemented")
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

type SerialSet struct {
	setData map[string]struct{}
}

func NewSerialSet() *SerialSet {
	return &SerialSet{
		setData: make(map[string]struct{}),
	}
}

func (s *SerialSet) Add(serial Serial) bool {
	_, alreadyExisted := s.setData[serial.ID()]
	s.setData[serial.ID()] = struct{}{}
	return !alreadyExisted
}

func NewSerialFromBytes(b []byte) Serial {
	obj := Serial{
		serial: b,
	}
	return obj
}

func NewSerialFromIDString(s string) (Serial, error) {
	bytes, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		return Serial{}, err
	}
	return NewSerialFromBytes(bytes), nil
}

func (s SerialSet) List() []Serial {
	serialList := make([]Serial, 0, len(s.setData))
	for idString := range s.setData {
		serial, _ := NewSerialFromIDString(idString)
		serialList = append(serialList, serial)
	}
	return serialList
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
