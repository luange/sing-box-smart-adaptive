package adaptive

import (
	"bytes"
	"errors"
	"sort"
	"sync/atomic"
	"time"

	N "github.com/sagernet/sing/common/network"
)

var (
	ErrNoEligibleCandidates      = errors.New("adaptive pool has no eligible candidates")
	ErrStrictAffinityUnavailable = errors.New("adaptive strict-affinity lease is unavailable")
)

type DecisionReason string

const (
	ReasonManualPin       DecisionReason = "manual_pin"
	ReasonLease           DecisionReason = "session_lease"
	ReasonRanked          DecisionReason = "ranked_health"
	ReasonFallback        DecisionReason = "manual_pin_fallback"
	ReasonStrictNew       DecisionReason = "strict_affinity_new"
	ReasonBulkSpread      DecisionReason = "bulk_spread"
	ReasonBulkThroughput  DecisionReason = "bulk_throughput"
	ReasonWarmingFallback DecisionReason = "warming_fallback"
)

type DecisionPlan struct {
	RuntimeEpochID  RuntimeEpochID
	CatalogRevision CatalogRevision
	Generation      uint64
	Mode            PolicyMode
	Reason          DecisionReason
	Candidates      []Candidate
	health          *HealthStore
	service         ServiceContext
	allowBlocked    bool
}

func (p DecisionPlan) TryAcquireAttemptPermit(nodeID NodeID, at time.Time) (*AttemptPermit, bool) {
	if p.health == nil {
		return &AttemptPermit{}, true
	}
	var handle NodeHandle
	for _, candidate := range p.Candidates {
		if candidate.ID == nodeID {
			handle = candidate.Handle
			break
		}
	}
	if p.allowBlocked {
		return p.health.TryAcquireConnectionFallbackPermitHandle(handle, p.service.Transport, at)
	}
	return p.health.TryAcquireConnectionPermitHandle(handle, p.service.Transport, at)
}

type PolicyEngine struct {
	health        *HealthStore
	maxAttempts   int
	manualFailure string
	bulkSequence  *atomic.Uint64
}

func NewPolicyEngine(health *HealthStore, maxAttempts int, manualFailure string) *PolicyEngine {
	if maxAttempts <= 0 {
		maxAttempts = 3
	}
	if manualFailure == "" {
		manualFailure = "fallback"
	}
	return &PolicyEngine{health: health, maxAttempts: maxAttempts, manualFailure: manualFailure, bulkSequence: new(atomic.Uint64)}
}

func (e *PolicyEngine) BindBulkSequence(sequence *atomic.Uint64) *PolicyEngine {
	if e != nil && sequence != nil {
		e.bulkSequence = sequence
	}
	return e
}

func (e *PolicyEngine) Plan(snapshot *ExecutionSnapshot, service ServiceContext, lease *SessionLease, pinned *NodeID) (DecisionPlan, error) {
	if snapshot == nil {
		return DecisionPlan{}, ErrNoCandidates
	}
	eligible := make([]Candidate, 0, len(snapshot.Candidates))
	supported := make([]Candidate, 0, len(snapshot.Candidates))
	for _, candidate := range snapshot.Candidates {
		if !candidateSupports(candidate, service.Transport) {
			continue
		}
		supported = append(supported, candidate)
		if e.candidateBlocked(candidate, service) {
			continue
		}
		eligible = append(eligible, candidate)
	}
	if pinned != nil {
		if candidate, loaded := snapshot.Candidate(*pinned); loaded && candidateSupports(candidate, service.Transport) {
			if !e.candidateBlocked(candidate, service) {
				return e.plan(snapshot, ModeManual, ReasonManualPin, service, []Candidate{candidate}), nil
			}
			if e.manualFailure == "fail_closed" {
				return DecisionPlan{}, ErrNoEligibleCandidates
			}
		} else if e.manualFailure == "fail_closed" {
			return DecisionPlan{}, ErrNoEligibleCandidates
		}
	}
	mode := service.Mode
	if mode == "" {
		mode = ModeAdaptive
	}
	if len(eligible) == 0 {
		if len(supported) > 0 && (mode == ModeAdaptive || mode == ModeLatency || mode == ModeBulk) {
			plan := e.plan(snapshot, mode, ReasonWarmingFallback, service, limitCandidates(supported, e.maxAttempts))
			plan.allowBlocked = true
			return plan, nil
		}
		return DecisionPlan{}, ErrNoEligibleCandidates
	}
	if mode == ModeAdaptive && lease != nil {
		for index, candidate := range eligible {
			if candidate.ID == lease.NodeID && candidate.Handle.Slot == lease.NodeSlot && candidate.Handle.Version == lease.NodeVersion {
				moveCandidateFirst(eligible, index)
				return e.plan(snapshot, service.Mode, ReasonLease, service, limitCandidates(eligible, e.maxAttempts)), nil
			}
		}
	}
	sort.SliceStable(eligible, func(i, j int) bool {
		leftPriority, leftDelay := e.candidatePriority(eligible[i], service)
		rightPriority, rightDelay := e.candidatePriority(eligible[j], service)
		if leftPriority != rightPriority {
			return leftPriority < rightPriority
		}
		if mode == ModeBulk {
			leftService := e.health.StatusHandle(eligible[i].Handle, DomainService, "", service.ID)
			rightService := e.health.StatusHandle(eligible[j].Handle, DomainService, "", service.ID)
			leftKnown, rightKnown := leftService.ThroughputSamples >= 2, rightService.ThroughputSamples >= 2
			if leftKnown != rightKnown {
				return leftKnown
			}
			if leftKnown && leftService.ThroughputBPS != rightService.ThroughputBPS {
				return leftService.ThroughputBPS > rightService.ThroughputBPS
			}
		}
		if leftDelay == 0 {
			leftDelay = 10 * time.Second
		}
		if rightDelay == 0 {
			rightDelay = 10 * time.Second
		}
		if leftDelay != rightDelay {
			return leftDelay < rightDelay
		}
		return bytes.Compare(eligible[i].ID[:], eligible[j].ID[:]) < 0
	})
	if mode == ModeStrictAffinity && lease != nil {
		for index, candidate := range eligible {
			if candidate.ID == lease.NodeID && candidate.Handle.Slot == lease.NodeSlot && candidate.Handle.Version == lease.NodeVersion {
				moveCandidateFirst(eligible, index)
				return e.plan(snapshot, mode, ReasonLease, service, limitCandidates(eligible, e.maxAttempts)), nil
			}
		}
		// The leased handle is no longer eligible. Start a bounded sequential
		// failover plan; DialContext replaces the lease only after a candidate
		// actually connects.
	}
	reason := ReasonRanked
	if pinned != nil {
		reason = ReasonFallback
	}
	switch mode {
	case ModeStrictAffinity:
		return e.plan(snapshot, mode, ReasonStrictNew, service, limitCandidates(eligible, e.maxAttempts)), nil
	case ModeBulk:
		sequence := e.bulkSequence.Add(1)
		if hasTrustedBulkThroughput(e.health, eligible, service.ID) {
			if sequence%5 != 0 {
				return e.plan(snapshot, mode, ReasonBulkThroughput, service, limitCandidates(eligible, e.maxAttempts)), nil
			}
			eligible = rotateCandidates(eligible, int(sequence/5))
			return e.plan(snapshot, mode, ReasonBulkSpread, service, limitCandidates(eligible, e.maxAttempts)), nil
		}
		eligible = rotateCandidates(eligible, int(sequence-1))
		return e.plan(snapshot, mode, ReasonBulkSpread, service, limitCandidates(eligible, e.maxAttempts)), nil
	case ModeAdaptive:
		return e.plan(snapshot, mode, reason, service, limitCandidates(eligible, e.maxAttempts)), nil
	case ModeLatency:
		return e.plan(snapshot, mode, ReasonRanked, service, limitCandidates(eligible, e.maxAttempts)), nil
	default:
		return DecisionPlan{}, errors.New("adaptive policy mode is invalid")
	}
}

func modeUsesLease(mode PolicyMode) bool {
	return mode != ModeBulk && mode != ModeLatency
}

// candidatePriority combines generic endpoint health with transport- and
// service-specific evidence. A node that passes a generic URL test but fails a
// real TCP/UDP connection is therefore ranked below a proven working node.
func (e *PolicyEngine) candidatePriority(candidate Candidate, service ServiceContext) (int, time.Duration) {
	statuses := []HealthStatus{
		e.health.EndpointHandle(candidate.Handle),
		e.health.StatusHandle(candidate.Handle, DomainTransport, service.Transport, ""),
		e.health.StatusHandle(candidate.Handle, DomainService, "", service.ID),
	}
	priority := healthPriority(HealthHealthy)
	var delay time.Duration
	for _, status := range statuses {
		if current := healthPriority(status.Health); current > priority {
			priority = current
		}
		if status.LastDelay > 0 && (delay == 0 || status.LastDelay > delay) {
			delay = status.LastDelay
		}
	}
	return priority, delay
}

func hasTrustedBulkThroughput(health *HealthStore, candidates []Candidate, serviceID string) bool {
	if health == nil {
		return false
	}
	for _, candidate := range candidates {
		if health.StatusHandle(candidate.Handle, DomainService, "", serviceID).ThroughputSamples >= 2 {
			return true
		}
	}
	return false
}

func (e *PolicyEngine) plan(snapshot *ExecutionSnapshot, mode PolicyMode, reason DecisionReason, service ServiceContext, candidates []Candidate) DecisionPlan {
	return DecisionPlan{RuntimeEpochID: snapshot.RuntimeEpochID, CatalogRevision: snapshot.CatalogRevision, Generation: snapshot.Generation, Mode: mode, Reason: reason, Candidates: candidates, health: e.health, service: service}
}

func (e *PolicyEngine) candidateBlocked(candidate Candidate, service ServiceContext) bool {
	return !e.health.CanAttemptHandle(candidate.Handle, service, time.Time{})
}

func candidateSupports(candidate Candidate, transport string) bool {
	for _, network := range candidate.Transport {
		if N.NetworkName(network) == N.NetworkName(transport) {
			return true
		}
	}
	return false
}

func healthPriority(state HealthState) int {
	switch state {
	case HealthHealthy:
		return 0
	case HealthUnknown:
		return 1
	case HealthDegraded:
		return 2
	case HealthUnreachable:
		return 4
	default:
		return 3
	}
}

func moveCandidateFirst(candidates []Candidate, index int) {
	if index <= 0 || index >= len(candidates) {
		return
	}
	candidate := candidates[index]
	copy(candidates[1:index+1], candidates[:index])
	candidates[0] = candidate
}

func limitCandidates(candidates []Candidate, limit int) []Candidate {
	if len(candidates) > limit {
		candidates = candidates[:limit]
	}
	return candidates
}

func rotateCandidates(candidates []Candidate, offset int) []Candidate {
	if len(candidates) < 2 {
		return candidates
	}
	offset %= len(candidates)
	if offset == 0 {
		return candidates
	}
	rotated := make([]Candidate, 0, len(candidates))
	rotated = append(rotated, candidates[offset:]...)
	rotated = append(rotated, candidates[:offset]...)
	return rotated
}
