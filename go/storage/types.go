package storage

import (
	"fmt"
	"time"

	"github.com/mozilla/crlite/go"
)

type RemoteCache interface {
	Exists(key string) (bool, error)
	SetInsert(key string, aEntry string) (bool, error)
	SetRemove(key string, aEntries []string) error
	SetContains(key string, aEntry string) (bool, error)
	SetList(key string) ([]string, error)
	SetToChan(key string, c chan<- string) error
	SetCardinality(key string) (int, error)
	ExpireAt(key string, aExpTime time.Time) error
	KeysToChan(pattern string, c chan<- string) error
	StoreLogState(aLogObj *types.CTLogState) error
	LoadLogState(aLogUrl string) (*types.CTLogState, error)
	LoadAllLogStates() ([]types.CTLogState, error)
	Migrate(logData *types.CTLogMetadata) error
	AcquireCommitLock() (*string, error)
	ReleaseCommitLock(aToken string)
	HasCommitLock(aToken string) (bool, error)
	GetEpoch() (uint64, error)
	NextEpoch() error
	Restore(aEpoch uint64, aLogStates []types.CTLogState) error
	AddPreIssuerAlias(aPreIssuer types.Issuer, aIssuer types.Issuer) error
	GetPreIssuerAliases(aPreIssuer types.Issuer) ([]types.Issuer, error)
	SetInsertMany(items []SetMemberWithExpiry) error
}

type SerialCacheKey struct {
	expDate   types.ExpDate
	issuer    types.Issuer
	id        string
	expirySet bool
}

func NewSerialCacheKey(aExpDate types.ExpDate, aIssuer types.Issuer) *SerialCacheKey {
	return &SerialCacheKey{
		expDate:   aExpDate,
		issuer:    aIssuer,
		id:        fmt.Sprintf("serials::%s::%s", aExpDate.ID(), aIssuer.ID()),
		expirySet: false,
	}
}

func (k *SerialCacheKey) ID() string {
	return k.id
}

func (k *SerialCacheKey) NewMember(serial types.Serial) SetMemberWithExpiry {
	return SetMemberWithExpiry{
		Key:    k.ID(),
		Value:  serial.BinaryString(),
		Expiry: k.expDate.ExpireTime(),
	}
}

type SetMemberWithExpiry struct {
	Key    string
	Value  string
	Expiry time.Time
}
