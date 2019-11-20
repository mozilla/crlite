package coordinator

import (
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jcjones/ct-mapreduce/storage"
)

var kRedisHost = "RedisHost"

func getRedisCache(tb testing.TB) (*storage.RedisCache, bool) {
	setting, ok := os.LookupEnv(kRedisHost)
	if !ok {
		tb.Skipf("%s is not set, unable to run %s. Skipping.", kRedisHost, tb.Name())
		return nil, true
	}
	tb.Logf("Connecting to Redis instance at %s", setting)

	rc, err := storage.NewRedisCache(setting, time.Second)
	if err != nil {
		tb.Errorf("Couldn't construct RedisCache: %v", err)
	}
	return rc, false
}

func Test_LeaderElectionSolo(t *testing.T) {
	r, exit := getRedisCache(t)
	if exit {
		return
	}
	c := NewCoordinator(r, "Test_LeaderElection")
	c.KeyLifeInitial = time.Second
	c.KeyLifeRenewal = time.Second

	lead, err := c.AwaitLeader()
	if err != nil {
		t.Error(err)
	}
	if lead != true {
		t.Errorf("Should have trivially been the leader")
	}
}

func tryLeaderElection(t *testing.T, r *storage.RedisCache, name string,
	resultChan chan<- bool) {
	c := NewCoordinator(r, name)
	c.KeyLifeInitial = time.Second
	c.KeyLifeRenewal = time.Second

	lead, err := c.AwaitLeader()
	if err != nil {
		t.Error(err)
	}

	resultChan <- lead
}

func Test_LeaderElectionPair(t *testing.T) {
	t.Parallel()
	c := make(chan bool)
	r, exit := getRedisCache(t)
	if exit {
		return
	}

	go tryLeaderElection(t, r, "Test_LeaderElectionPair", c)
	go tryLeaderElection(t, r, "Test_LeaderElectionPair", c)

	resultOne := <-c
	resultTwo := <-c

	if resultOne == resultTwo {
		t.Errorf("Expected only one leader: %v %v", resultOne, resultTwo)
	}
}

func Test_LeaderElectionFourty(t *testing.T) {
	t.Parallel()
	r, exit := getRedisCache(t)
	if exit {
		return
	}
	c := make(chan bool)

	max := 40
	for i := 0; i < max; i++ {
		go tryLeaderElection(t, r, "Test_LeaderElectionFourty", c)
	}

	leaderCount := 0
	for i := 0; i < max; i++ {
		result := <-c
		if result {
			leaderCount++
		}
	}

	if leaderCount != 1 {
		t.Errorf("Expected exactly one leader, got %d", leaderCount)
	}
}

func Test_StartPreconditions(t *testing.T) {
	t.Parallel()
	r, exit := getRedisCache(t)
	if exit {
		return
	}
	c := NewCoordinator(r, "Test_StartPreconditions")

	err := c.AwaitStart()
	if err == nil {
		t.Errorf("Expected error because leader not elected")
	}

	err = c.SendStart()
	if err == nil {
		t.Errorf("Expected error because leader not elected")
	}

	c.identifier = "override"
	err = c.SendStart()
	if err == nil {
		t.Errorf("Expected error because not leader")
	}

	c.isLeader = true
	err = c.AwaitStart()
	if err == nil {
		t.Errorf("Expected error because not follower")
	}
}

func Test_Start(t *testing.T) {
	t.Parallel()
	r, exit := getRedisCache(t)
	if exit {
		return
	}

	wg := sync.WaitGroup{}

	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			c := NewCoordinator(r, "Test_Start")
			c.KeyLifeInitial = time.Second
			c.KeyLifeRenewal = time.Second
			c.identifier = "test-identifier"

			err := c.AwaitStart()
			if err != nil {
				t.Error(err)
			}
			wg.Done()
		}()
	}

	go func() {
		c := NewCoordinator(r, "Test_Start")
		c.KeyLifeInitial = time.Second
		c.KeyLifeRenewal = time.Second
		c.identifier = "test-identifier"
		c.isLeader = true

		time.Sleep(10 * time.Millisecond)
		err := c.SendStart()
		if err != nil {
			t.Error(err)
		}
	}()

	wg.Wait()
}

func Test_LeaderExtension(t *testing.T) {
	t.Parallel()

	r, exit := getRedisCache(t)
	if exit {
		return
	}
	c := NewCoordinator(r, "Test_LeaderExtension")
	c.KeyLifeInitial = time.Second
	c.KeyLifeRenewal = time.Second
	c.RenewalPeriod = 250 * time.Millisecond

	lead, err := c.AwaitLeader()
	if err != nil {
		t.Error(err)
	}
	if lead != true {
		t.Errorf("Should have trivially been the leader")
	}
	err = c.SendStart()
	if err != nil {
		t.Error(err)
	}

	time.Sleep(2 * time.Second)

	leader, err := r.Exists(kLeaderKey + c.name)
	if err != nil {
		t.Error(err)
	}
	started, err := r.Exists(kStartedKey + c.identifier)
	if err != nil {
		t.Error(err)
	}

	if !leader {
		t.Error("Expected leader to still exist")
	}
	if !started {
		t.Error("Expected started to still exist")
	}
}
