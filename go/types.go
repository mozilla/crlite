package types

import (
	"math/big"
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
	Issuer  string
}

type IssuerRevocations struct {
	Issuer         string
	RevokedSerials []*big.Int
}

func (self IssuerRevocations) Merge(other IssuerRevocations) {
}

type CrlTuple struct {
	Issuer string
	Url    string
}
