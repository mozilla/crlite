package storage

import (
	"encoding/binary"
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

func (k *SerialCacheKey) NewMember(aTimestamp uint64, aLogId [32]byte, serial types.Serial) SetMemberWithExpiry {
	binarySerial := serial.BinaryString()

	// The set member is the concatenation of the timestamp, logID, and serial number
	value := make([]byte, 8+32+len(binarySerial))
	binary.LittleEndian.PutUint64(value, aTimestamp)
	copy(value[8:40], aLogId[:])
	copy(value[40:], binarySerial)

	return SetMemberWithExpiry{
		Key:    k.ID(),
		Value:  string(value),
		Expiry: k.expDate.ExpireTime(),
	}
}

type SetMemberWithExpiry struct {
	Key    string
	Value  string
	Expiry time.Time
}

type SerialCacheEntry string

func (s SerialCacheEntry) AsSerial() (types.Serial, error) {
	if len(s) < 40 {
		// The entire entry is a serial number
		serial, err := types.NewSerialFromBinaryString(string(s))
		return serial, err
	}
	serial, err := types.NewSerialFromBinaryString(string(s[40:]))
	return serial, err
}

func (s SerialCacheEntry) IsCovered(aCoverageMap *types.CoverageCutoffMap) bool {
	if len(s) < 40 {
		// This is a raw serial number with no CT log timestamp. We
		// need to treat it as covered to ensure that it moves to
		// storage. This may cause us to mask a revoked serial with a
		// "not covered" status.
		return true
	}
	timestamp := binary.LittleEndian.Uint64([]byte(s[0:8]))
	logId := []byte(s[8:40])

	cutoff, prs := (*aCoverageMap)[[32]byte(logId)]
	if !prs {
		// Unclear how we learned about this serial number if there's
		// no matching log, but it's definitely not covered. The cache
		// entry will persist until the log is added or the certificate
		// expires.
		return false
	}
	return timestamp <= cutoff
}
