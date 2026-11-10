package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/golang/glog"
	"github.com/mozilla/crlite/go/config"
	"github.com/mozilla/crlite/go/engine"
)

const (
	permMode    = 0644
	permModeDir = 0755
)

var (
	ctconfig = config.NewCTConfig()
)

func work() error {
	ctconfig.Init()

	ctx := context.Background()
	ctx, cancelMain := context.WithCancel(ctx)

	// Try to handle SIGINT and SIGTERM gracefully
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	defer close(sigChan)
	go func() {
		sig := <-sigChan
		glog.Infof("Signal caught: %s..", sig)
		cancelMain()
		signal.Stop(sigChan) // Restore default behavior
	}()

	certDB, cache := engine.GetConfiguredStorage(ctx, ctconfig, false)
	defer glog.Flush()

	glog.Infof("Committing DB changes since last run")
	commitToken, err := cache.AcquireCommitLock()
	if err != nil {
		return fmt.Errorf("Failed to acquire commit lock: %s", err)
	}
	if commitToken == nil {
		// The lock is usually held by aggregate-known, which commits
		// before it reads serials from storage, so there's nothing
		// for us to do. If this happens on every run then the lock
		// may have been orphaned; it expires after
		// storage.COMMIT_LOCK_EXPIRATION.
		glog.Warningf("Skipping commit: the commit lock is held by another process")
		return nil
	}
	defer cache.ReleaseCommitLock(*commitToken)

	err = certDB.Commit(ctx, *commitToken)
	if err != nil {
		return fmt.Errorf("Error in commit: %s", err)
	}

	return nil
}

func main() {
	err := work()
	if err != nil {
		glog.Fatal(err)
	}
}
