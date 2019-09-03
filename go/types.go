package types

import (
	"encoding/asn1"
	"net/url"
	"time"

	"github.com/jcjones/ct-mapreduce/storage"
)

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

type MetadataTuple struct {
	ExpDate string
	Issuer  storage.Issuer
}

type IssuerRevocations struct {
	Issuer         storage.Issuer
	RevokedSerials []storage.Serial
}

func (self IssuerRevocations) Merge(other IssuerRevocations) {
	panic("Not implemented")
}

type IssuerCrlUrls struct {
	Issuer storage.Issuer
	Urls   []url.URL
}

type IssuerCrlPaths struct {
	Issuer   storage.Issuer
	CrlPaths []string
}

type RawCertificateList struct {
	TBSCertList        TBSCertificateListWithRawSerials
	SignatureAlgorithm asn1.RawValue
	SignatureValue     asn1.BitString
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

func DecodeRawCertList(data []byte) (*TBSCertificateListWithRawSerials, error) {
	var certList RawCertificateList
	_, err := asn1.Unmarshal(data, &certList)
	tbsCertList := certList.TBSCertList
	return &tbsCertList, err
}

func DecodeRawTBSCertList(data []byte) (*TBSCertificateListWithRawSerials, error) {
	var tbsCertList TBSCertificateListWithRawSerials
	_, err := asn1.Unmarshal(data, &tbsCertList)
	return &tbsCertList, err
}
