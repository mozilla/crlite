package types

import (
	"encoding/asn1"
	"net/url"
	"time"

	"github.com/mozilla/crlite/go/storage"
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
	IssuerDN string
	CrlPaths []string
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

func (s *SerialSet) Add(serial storage.Serial) bool {
	_, alreadyExisted := s.setData[serial.ID()]
	s.setData[serial.ID()] = struct{}{}
	return !alreadyExisted
}

func (s SerialSet) List() []storage.Serial {
	serialList := make([]storage.Serial, 0, len(s.setData))
	for idString := range s.setData {
		serial, _ := storage.NewSerialFromIDString(idString)
		serialList = append(serialList, serial)
	}
	return serialList
}
