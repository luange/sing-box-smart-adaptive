package interrupt

import (
	"net"
	"testing"
	"time"
)

func TestInterruptSelectiveTargetsPreviousCandidateAndKeepsLongActive(t *testing.T) {
	group := NewGroup()
	now := time.Now()
	var peers []net.Conn
	add := func(key string, createdAt, lastActive time.Time) net.Conn {
		left, right := net.Pipe()
		peers = append(peers, right)
		wrapped := group.NewConnWithKey(left, true, false, key)
		item := wrapped.(*Conn).element.Value
		item.createdAt = createdAt
		item.lastActive.Store(lastActive.UnixNano())
		return wrapped
	}
	defer func() {
		for _, peer := range peers {
			_ = peer.Close()
		}
	}()

	for range 3 {
		add("old", now.Add(-20*time.Second), now.Add(-15*time.Second))
	}
	for range 4 {
		add("old", now.Add(-5*time.Second), now)
	}
	for range 3 {
		add("old", now.Add(-time.Minute), now)
	}
	add("new", now.Add(-time.Minute), now.Add(-time.Minute))

	result := group.InterruptSelective(InterruptPolicy{
		IdleThreshold: 10 * time.Second,
		LongConnAge:   30 * time.Second,
		TargetKey:     "old",
	})
	if result.Interrupted != 7 || result.Idle != 3 || result.Short != 4 {
		t.Fatalf("unexpected interrupted result: %+v", result)
	}
	if result.Kept != 4 || result.KeptLong != 3 {
		t.Fatalf("unexpected kept result: %+v", result)
	}
}

func TestInterruptSelectiveForceAllOnlyTargetsSelectedCandidate(t *testing.T) {
	group := NewGroup()
	oldLeft, oldRight := net.Pipe()
	defer oldRight.Close()
	newLeft, newRight := net.Pipe()
	defer newRight.Close()
	group.NewConnWithKey(oldLeft, true, false, "old")
	group.NewConnWithKey(newLeft, true, false, "new")

	result := group.InterruptSelective(InterruptPolicy{ForceAll: true, TargetKey: "old"})
	if result.Interrupted != 1 || result.Kept != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
}
