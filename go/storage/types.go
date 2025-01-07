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
	ExpireIn(key string, aDur time.Duration) error
	Queue(key string, identifier string) (int64, error)
	Pop(key string) (string, error)
	QueueLength(key string) (int64, error)
	BlockingPopCopy(key string, dest string, timeout time.Duration) (string, error)
	ListRemove(key string, value string) error
	TrySet(k string, v string, life time.Duration) (string, error)
	KeysToChan(pattern string, c chan<- string) error
	StoreLogState(aLogObj *types.CTLogState) error
	LoadLogState(aLogUrl string) (*types.CTLogState, error)
	LoadAllLogStates() ([]types.CTLogState, error)
	Migrate(logData *types.CTLogMetadata) error
}
