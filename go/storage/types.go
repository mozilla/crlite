package storage

import (
	"time"

	"github.com/mozilla/crlite/go"
)

type RemoteCache interface {
	Exists(key string) (bool, error)
	SetInsert(key string, aEntry string) (bool, error)
	SetRemove(key string, entry string) (bool, error)
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
}
