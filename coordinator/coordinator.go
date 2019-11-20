/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package coordinator

import (
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/golang/glog"
	"github.com/jcjones/ct-mapreduce/storage"
)

const kLeaderKey string = "leader-"
const kStartedKey string = "started-"

type Coordinator struct {
	cache            storage.RemoteCache
	name             string
	isLeader         bool
	identifier       string
	KeyLifeInitial   time.Duration
	KeyLifeRenewal   time.Duration
	RenewalPeriod    time.Duration
	AwaitSleepPeriod time.Duration
}

func NewCoordinator(cache storage.RemoteCache, name string) Coordinator {
	return Coordinator{
		cache:            cache,
		name:             name,
		isLeader:         false,
		identifier:       "",
		KeyLifeInitial:   5 * time.Minute,
		KeyLifeRenewal:   2 * time.Minute,
		RenewalPeriod:    time.Minute,
		AwaitSleepPeriod: 250 * time.Millisecond,
	}
}

func (c *Coordinator) AwaitLeader() (bool, error) {
	glog.Infof("Awaiting leader")

	randomSource := rand.New(rand.NewSource(time.Now().UnixNano()))

	hostname, err := os.Hostname()
	if err != nil {
		return false, err
	}
	ourIdentifier := fmt.Sprintf("%s-%X", hostname, randomSource.Int63())
	glog.V(1).Infof("Our identifier is %s", ourIdentifier)

	leaderKey := kLeaderKey + c.name
	result, err := c.cache.TrySet(leaderKey, ourIdentifier, c.KeyLifeInitial)
	if err != nil {
		return false, err
	}

	c.identifier = result
	c.isLeader = c.identifier == ourIdentifier

	if c.isLeader {
		glog.Infof("We've been elected leader, our name is %s", c.identifier)
		started, err := c.cache.Exists(kStartedKey + c.identifier)
		if err != nil && started {
			glog.Fatalf("Apparently already started, but we're the leader. Aborting.")
		}
		go func() {
			for {
				err := c.cache.ExpireIn(leaderKey, c.KeyLifeRenewal)
				if err != nil {
					glog.Warningf("Failed to update our leadership expiration: %s", err)
				}
				time.Sleep(c.RenewalPeriod)
				glog.V(1).Infof("Re-announcing our leadership.")
			}
		}()
	}

	glog.V(1).Infof("Leader=%v Identifier=%s", c.isLeader, c.identifier)
	return c.isLeader, nil
}

func (c Coordinator) AwaitStart() error {
	if len(c.identifier) == 0 {
		return fmt.Errorf("Must not call before AwaitLeader completes")
	}
	if c.isLeader {
		return fmt.Errorf("Must not call unless we're a follower")
	}

	for {
		started, err := c.cache.Exists(kStartedKey + c.identifier)
		if err != nil {
			return err
		}
		if started {
			glog.Infof("Received start.")
			return nil
		}
		time.Sleep(c.AwaitSleepPeriod)
	}
}

func (c Coordinator) SendStart() error {
	if len(c.identifier) == 0 {
		return fmt.Errorf("Must not call before AwaitLeader completes")
	}
	if !c.isLeader {
		return fmt.Errorf("Must not call unless we're leader")
	}

	startedKey := kStartedKey + c.identifier
	result, err := c.cache.TrySet(startedKey, c.identifier, c.KeyLifeInitial)
	if err != nil {
		return err
	}
	if result != c.identifier {
		glog.Fatalf("Redis error: TrySet should have succeeded, put %s got %s", c.identifier, result)
	}

	go func() {
		for {
			err := c.cache.ExpireIn(startedKey, c.KeyLifeRenewal)
			if err != nil {
				glog.Warningf("Failed to update our start expiration: %s", err)
			}
			time.Sleep(c.RenewalPeriod)
			glog.V(1).Infof("Re-announcing our start.")
		}
	}()

	glog.Infof("Sent start.")
	return nil
}
