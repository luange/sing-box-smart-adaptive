package adaptive

import (
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

const switchAuditLimit = 64
const pendingSwitchLimit = 1024

type pendingSwitchFailure struct {
	serviceID string
	node      NodeHandle
	tag       string
	failure   FailureClass
	at        time.Time
}

type SwitchAuditStore struct {
	access  sync.Mutex
	entries []adapter.AdaptiveSwitchAudit
	pending map[SessionKey]pendingSwitchFailure
	total   uint64
}

func NewSwitchAuditStore() *SwitchAuditStore {
	return &SwitchAuditStore{pending: make(map[SessionKey]pendingSwitchFailure)}
}

func (s *SwitchAuditStore) RecordFailure(session SessionKey, serviceID string, candidate Candidate, failure FailureClass, at time.Time) {
	if s == nil || session == (SessionKey{}) || candidate.ID == (NodeID{}) || serviceID == "" {
		return
	}
	s.access.Lock()
	if len(s.pending) >= pendingSwitchLimit {
		for key, item := range s.pending {
			if at.Sub(item.at) > 10*time.Minute {
				delete(s.pending, key)
			}
		}
	}
	if len(s.pending) < pendingSwitchLimit {
		s.pending[session] = pendingSwitchFailure{serviceID: serviceID, node: candidate.Handle, tag: safePersistentTag(candidate.PrimaryTag), failure: failure, at: at}
	}
	s.access.Unlock()
}

func (s *SwitchAuditStore) RecordSelection(session SessionKey, serviceID string, previous NodeHandle, candidate Candidate, reason DecisionReason, at time.Time) {
	if s == nil || candidate.ID == (NodeID{}) || serviceID == "" {
		return
	}
	s.access.Lock()
	pending, failed := s.pending[session]
	if failed {
		delete(s.pending, session)
	}
	if !failed && (previous.NodeID == (NodeID{}) || previous == candidate.Handle) {
		s.access.Unlock()
		return
	}
	event := adapter.AdaptiveSwitchAudit{
		ServiceID: serviceID, NewNodeID: candidate.ID.String(), NewTag: safePersistentTag(candidate.PrimaryTag),
		Reason: string(reason), OccurredAt: at,
	}
	if failed {
		event.OldNodeID, event.OldTag = pending.node.NodeID.String(), pending.tag
		event.Failure = string(pending.failure)
		event.Reason = "failure_failover"
	} else {
		event.OldNodeID = previous.NodeID.String()
	}
	s.entries = append(s.entries, event)
	if len(s.entries) > switchAuditLimit {
		copy(s.entries, s.entries[len(s.entries)-switchAuditLimit:])
		s.entries = s.entries[:switchAuditLimit]
	}
	s.total++
	s.access.Unlock()
}

func (s *SwitchAuditStore) Snapshot() ([]adapter.AdaptiveSwitchAudit, uint64) {
	if s == nil {
		return nil, 0
	}
	s.access.Lock()
	entries := append([]adapter.AdaptiveSwitchAudit(nil), s.entries...)
	total := s.total
	s.access.Unlock()
	return entries, total
}
