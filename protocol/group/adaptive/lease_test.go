package adaptive

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestConcurrentFirstSessionHasSingleLeader(t *testing.T) {
	manager := NewSessionLeaseManager(128)
	key := SessionKey{1}
	nodeID := NodeID{9}
	var leaders atomic.Int64
	var waitGroup sync.WaitGroup
	errors := make(chan error, 100)
	for range 100 {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			lease, reservation, err := manager.Reserve(context.Background(), key, time.Now())
			if err != nil {
				errors <- err
				return
			}
			if reservation != nil {
				leaders.Add(1)
				time.Sleep(5 * time.Millisecond)
				lease = reservation.Commit(nodeID, "youtube", ModeStrictAffinity, time.Minute, time.Now())
			}
			if lease.NodeID != nodeID {
				errors <- ErrNoEligibleCandidates
			}
		}()
	}
	waitGroup.Wait()
	close(errors)
	for err := range errors {
		t.Fatal(err)
	}
	if leaders.Load() != 1 {
		t.Fatalf("concurrent first session elected %d leaders", leaders.Load())
	}
}

func TestLeaseManagerIsBounded(t *testing.T) {
	manager := NewSessionLeaseManager(3)
	now := time.Now()
	for index := 0; index < 5; index++ {
		_, reservation, err := manager.Reserve(context.Background(), SessionKey{byte(index)}, now)
		if err != nil {
			t.Fatal(err)
		}
		reservation.Commit(NodeID{byte(index)}, "service", ModeAdaptive, time.Minute, now)
	}
	active, evictions := manager.Stats()
	if active != 3 || evictions != 2 {
		t.Fatalf("lease bound mismatch: active=%d evictions=%d", active, evictions)
	}
}

func TestControlClearRejectsStaleReservationCommit(t *testing.T) {
	manager := NewSessionLeaseManager(8)
	key := SessionKey{1}
	_, reservation, err := manager.Reserve(context.Background(), key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	manager.Clear()
	committed := reservation.Commit(NodeID{1}, "youtube", ModeStrictAffinity, time.Minute, time.Now())
	if committed != (SessionLease{}) {
		t.Fatalf("stale reservation unexpectedly committed: %+v", committed)
	}
	if _, loaded := manager.Peek(key, time.Now()); loaded {
		t.Fatal("stale reservation restored a lease after control change")
	}
}

func TestLeaseClearWakesExistingWaiter(t *testing.T) {
	manager := NewSessionLeaseManager(8)
	key := SessionKey{9}
	_, first, err := manager.Reserve(context.Background(), key, time.Now())
	if err != nil || first == nil {
		t.Fatalf("first reservation failed: reservation=%v err=%v", first, err)
	}

	woke := make(chan *LeaseReservation, 1)
	errors := make(chan error, 1)
	go func() {
		_, reservation, reserveErr := manager.Reserve(context.Background(), key, time.Now())
		if reserveErr != nil {
			errors <- reserveErr
			return
		}
		woke <- reservation
	}()

	deadline := time.Now().Add(time.Second)
	for {
		manager.access.Lock()
		pending := manager.pending[key]
		waiters := 0
		if pending != nil {
			waiters = pending.waiters
		}
		manager.access.Unlock()
		if waiters == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("waiter did not enter pending state")
		}
		time.Sleep(time.Millisecond)
	}

	manager.Clear()
	select {
	case err = <-errors:
		t.Fatal(err)
	case second := <-woke:
		if second == nil {
			t.Fatal("woken waiter did not reserve the cleared lease")
		}
		second.Abort()
	case <-time.After(time.Second):
		t.Fatal("clear did not wake pending waiter")
	}

	first.Abort()
}

func TestOldReservationCannotCloseNewGenerationPending(t *testing.T) {
	manager := NewSessionLeaseManager(8)
	key := SessionKey{10}
	_, first, err := manager.Reserve(context.Background(), key, time.Now())
	if err != nil || first == nil {
		t.Fatalf("first reservation failed: reservation=%v err=%v", first, err)
	}

	manager.Clear()
	_, second, err := manager.Reserve(context.Background(), key, time.Now())
	if err != nil || second == nil {
		t.Fatalf("second reservation failed: reservation=%v err=%v", second, err)
	}
	if committed := first.Commit(NodeID{1}, "stale", ModeAdaptive, time.Minute, time.Now()); committed != (SessionLease{}) {
		t.Fatalf("old generation committed over new pending: %+v", committed)
	}
	first.Abort()

	thirdResult := make(chan SessionLease, 1)
	thirdError := make(chan error, 1)
	go func() {
		lease, reservation, reserveErr := manager.Reserve(context.Background(), key, time.Now())
		if reserveErr != nil {
			thirdError <- reserveErr
			return
		}
		if reservation != nil {
			thirdError <- ErrNoEligibleCandidates
			return
		}
		thirdResult <- lease
	}()

	deadline := time.Now().Add(time.Second)
	for {
		manager.access.Lock()
		pending := manager.pending[key]
		waiters := 0
		if pending != nil {
			waiters = pending.waiters
		}
		manager.access.Unlock()
		if waiters == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("third reservation did not wait on second")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case lease := <-thirdResult:
		t.Fatalf("old reservation woke third before second commit: %+v", lease)
	case err = <-thirdError:
		t.Fatal(err)
	default:
	}

	expected := NodeID{2}
	second.Commit(expected, "youtube", ModeStrictAffinity, time.Minute, time.Now())
	select {
	case lease := <-thirdResult:
		if lease.NodeID != expected {
			t.Fatalf("third received wrong lease: %+v", lease)
		}
	case err = <-thirdError:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("second commit did not wake third")
	}
}
