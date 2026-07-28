package adaptive

import (
	"strings"
	"testing"
	"time"
)

func TestSwitchAuditJoinsFailureWithReplacementWithoutPrivateDestination(t *testing.T) {
	store := NewSwitchAuditStore()
	session := SessionKey{1}
	old := Candidate{ID: NodeID{1}, Handle: NodeHandle{NodeID: NodeID{1}, Slot: 1, Version: 1}, PrimaryTag: "old-node"}
	next := Candidate{ID: NodeID{2}, Handle: NodeHandle{NodeID: NodeID{2}, Slot: 2, Version: 1}, PrimaryTag: "new-node"}
	store.RecordFailure(session, "chatgpt_web", old, FailureTLS, time.Now())
	store.RecordSelection(session, "chatgpt_web", NodeHandle{}, next, ReasonStrictNew, time.Now())
	entries, total := store.Snapshot()
	if total != 1 || len(entries) != 1 {
		t.Fatalf("switch audit missing: total=%d entries=%+v", total, entries)
	}
	event := entries[0]
	if event.OldNodeID != old.ID.String() || event.NewNodeID != next.ID.String() || event.Failure != string(FailureTLS) || event.Reason != "failure_failover" {
		t.Fatalf("switch audit mismatch: %+v", event)
	}
	if strings.Contains(event.ServiceID+event.OldTag+event.NewTag, "?") || strings.Contains(event.ServiceID+event.OldTag+event.NewTag, "token") {
		t.Fatalf("private destination entered switch audit: %+v", event)
	}
}

func TestSwitchAuditIsBounded(t *testing.T) {
	store := NewSwitchAuditStore()
	for index := 0; index < switchAuditLimit+20; index++ {
		session := SessionKey{byte(index + 1)}
		old := Candidate{ID: NodeID{byte(index + 1)}, Handle: NodeHandle{NodeID: NodeID{byte(index + 1)}, Slot: 1, Version: 1}, PrimaryTag: "old"}
		next := Candidate{ID: NodeID{byte(index + 2)}, Handle: NodeHandle{NodeID: NodeID{byte(index + 2)}, Slot: 2, Version: 1}, PrimaryTag: "new"}
		store.RecordFailure(session, "service:test", old, FailureConnect, time.Now())
		store.RecordSelection(session, "service:test", NodeHandle{}, next, ReasonRanked, time.Now())
	}
	entries, total := store.Snapshot()
	if len(entries) != switchAuditLimit || total != switchAuditLimit+20 {
		t.Fatalf("switch audit bound failed: entries=%d total=%d", len(entries), total)
	}
}
