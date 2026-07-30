package adaptive

import (
	"bytes"
	"errors"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/common/nodeweight"
	N "github.com/sagernet/sing/common/network"
)

var (
	ErrNoEligibleCandidates      = errors.New("adaptive pool has no eligible candidates")
	ErrStrictAffinityUnavailable = errors.New("adaptive strict-affinity lease is unavailable")
)

const (
	defaultSwitchMargin   = 0.15
	defaultSwitchCooldown = 2 * time.Minute
	maxStickyEntries      = 4096
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
	ReasonStickyMargin    DecisionReason = "sticky_margin"
	ReasonSwitchCooldown  DecisionReason = "switch_cooldown"
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
		return p.health.TryAcquireConnectionFallbackPermitHandle(handle, serviceHealthTransport(p.service), at)
	}
	return p.health.TryAcquireConnectionPermitHandle(handle, serviceHealthTransport(p.service), at)
}

type stickyPreference struct {
	handle    NodeHandle
	until     time.Time
	updatedAt time.Time
}

type PolicyEngine struct {
	health         *HealthStore
	maxAttempts    int
	manualFailure  string
	bulkSequence   *atomic.Uint64
	nodeWeights    *nodeweight.Matcher
	switchMargin   float64
	switchCooldown time.Duration
	stickyAccess   sync.Mutex
	sticky         map[string]stickyPreference
}

func NewPolicyEngine(health *HealthStore, maxAttempts int, manualFailure string) *PolicyEngine {
	if maxAttempts <= 0 {
		maxAttempts = 3
	}
	if manualFailure == "" {
		manualFailure = "fallback"
	}
	return &PolicyEngine{
		health:         health,
		maxAttempts:    maxAttempts,
		manualFailure:  manualFailure,
		bulkSequence:   new(atomic.Uint64),
		switchMargin:   defaultSwitchMargin,
		switchCooldown: defaultSwitchCooldown,
		sticky:         make(map[string]stickyPreference),
	}
}

func (e *PolicyEngine) BindBulkSequence(sequence *atomic.Uint64) *PolicyEngine {
	if e != nil && sequence != nil {
		e.bulkSequence = sequence
	}
	return e
}

func (e *PolicyEngine) BindNodeWeights(weights *nodeweight.Matcher) *PolicyEngine {
	if e != nil {
		e.nodeWeights = weights
	}
	return e
}

func (e *PolicyEngine) BindSwitchStability(margin float64, cooldown time.Duration) *PolicyEngine {
	if e == nil {
		return e
	}
	if margin < 0 {
		margin = defaultSwitchMargin
	}
	if margin > 0.5 {
		margin = 0.5
	}
	if cooldown < 0 {
		cooldown = 0
	}
	e.switchMargin = margin
	e.switchCooldown = cooldown
	return e
}

// Clear drops sticky selection state. Called on pool retire/reload so process
// lifetime health conclusions and sticky maps cannot leak across epochs.
func (e *PolicyEngine) Clear() {
	if e == nil {
		return
	}
	e.stickyAccess.Lock()
	e.sticky = make(map[string]stickyPreference)
	e.stickyAccess.Unlock()
}

// RememberSelection records the live egress for a service affinity so later
// plans can apply delay hysteresis and a short switch cooldown.
func (e *PolicyEngine) RememberSelection(key string, handle NodeHandle, now time.Time) {
	if e == nil || key == "" || handle.NodeID == (NodeID{}) {
		return
	}
	if now.IsZero() {
		now = time.Now()
	}
	e.stickyAccess.Lock()
	defer e.stickyAccess.Unlock()
	if e.sticky == nil {
		e.sticky = make(map[string]stickyPreference)
	}
	previous, hadPrevious := e.sticky[key]
	until := previous.until
	if !hadPrevious || previous.handle != handle {
		if e.switchCooldown > 0 {
			until = now.Add(e.switchCooldown)
		} else {
			until = time.Time{}
		}
	}
	e.sticky[key] = stickyPreference{handle: handle, until: until, updatedAt: now}
	if len(e.sticky) > maxStickyEntries {
		e.pruneStickyLocked(now)
	}
}

func (e *PolicyEngine) stickyKey(service ServiceContext) string {
	base := service.ID
	if service.AffinityID != "" {
		base = service.AffinityID
	}
	if service.Session != (SessionKey{}) {
		return service.Session.String() + "\x00" + base
	}
	return base
}

func (e *PolicyEngine) stickyPreferred(key string, now time.Time) (stickyPreference, bool) {
	if e == nil || key == "" {
		return stickyPreference{}, false
	}
	if now.IsZero() {
		now = time.Now()
	}
	e.stickyAccess.Lock()
	defer e.stickyAccess.Unlock()
	pref, loaded := e.sticky[key]
	if !loaded || pref.handle.NodeID == (NodeID{}) {
		return stickyPreference{}, false
	}
	// Keep the last known preference even after cooldown so delay margin can
	// still damp ranking noise; cooldown only strengthens stickiness.
	if !pref.until.IsZero() && now.After(pref.until.Add(24*time.Hour)) {
		delete(e.sticky, key)
		return stickyPreference{}, false
	}
	return pref, true
}

func (e *PolicyEngine) pruneStickyLocked(now time.Time) {
	for key, pref := range e.sticky {
		if pref.until.IsZero() && now.Sub(pref.updatedAt) > 24*time.Hour {
			delete(e.sticky, key)
			continue
		}
		if !pref.until.IsZero() && now.After(pref.until.Add(24*time.Hour)) {
			delete(e.sticky, key)
		}
	}
	for len(e.sticky) > maxStickyEntries {
		var oldestKey string
		var oldest time.Time
		for key, pref := range e.sticky {
			if oldestKey == "" || pref.updatedAt.Before(oldest) {
				oldestKey = key
				oldest = pref.updatedAt
			}
		}
		delete(e.sticky, oldestKey)
	}
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
		leftScore := e.candidateScore(eligible[i], service)
		rightScore := e.candidateScore(eligible[j], service)
		if leftScore.HealthPriority != rightScore.HealthPriority {
			return leftScore.HealthPriority < rightScore.HealthPriority
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
		if leftScore.WeightedDelay != rightScore.WeightedDelay {
			return leftScore.WeightedDelay < rightScore.WeightedDelay
		}
		return bytes.Compare(eligible[i].ID[:], eligible[j].ID[:]) < 0
	})
	reason := ReasonRanked
	if pinned != nil {
		reason = ReasonFallback
	}
	if mode == ModeAdaptive {
		if stickyReason, ok := e.applyStickyStability(eligible, service, time.Now()); ok {
			reason = stickyReason
		}
	}
	if mode == ModeStrictAffinity && lease != nil {
		for index, candidate := range eligible {
			if candidate.ID == lease.NodeID && candidate.Handle.Slot == lease.NodeSlot && candidate.Handle.Version == lease.NodeVersion {
				// An established identity lease must not hedge or immediately fall
				// through to another egress. Retain the leased node until its
				// breaker excludes it; the next connection then performs bounded
				// failover and commits one new identity.
				return e.plan(snapshot, mode, ReasonLease, service, []Candidate{eligible[index]}), nil
			}
		}
		// The leased handle is no longer eligible. Start a bounded sequential
		// failover plan; DialContext replaces the lease only after a candidate
		// actually connects.
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
		return e.plan(snapshot, mode, reason, service, limitCandidates(eligible, e.maxAttempts)), nil
	default:
		return DecisionPlan{}, errors.New("adaptive policy mode is invalid")
	}
}

func (e *PolicyEngine) applyStickyStability(eligible []Candidate, service ServiceContext, now time.Time) (DecisionReason, bool) {
	pref, loaded := e.stickyPreferred(e.stickyKey(service), now)
	if !loaded {
		return "", false
	}
	incumbentIndex := -1
	for index, candidate := range eligible {
		if candidate.Handle == pref.handle || candidate.ID == pref.handle.NodeID && candidate.Handle.Slot == pref.handle.Slot && candidate.Handle.Version == pref.handle.Version {
			incumbentIndex = index
			break
		}
	}
	if incumbentIndex <= 0 {
		return "", false
	}
	challenger := eligible[0]
	incumbent := eligible[incumbentIndex]
	challengerScore := e.candidateScore(challenger, service)
	incumbentScore := e.candidateScore(incumbent, service)
	// A clearly healthier challenger always wins.
	if challengerScore.HealthPriority < incumbentScore.HealthPriority {
		return "", false
	}
	inCooldown := e.switchCooldown > 0 && !pref.until.IsZero() && !now.After(pref.until)
	if inCooldown {
		moveCandidateFirst(eligible, incumbentIndex)
		return ReasonSwitchCooldown, true
	}
	if challengerScore.HealthPriority > incumbentScore.HealthPriority {
		moveCandidateFirst(eligible, incumbentIndex)
		return ReasonStickyMargin, true
	}
	if !significantlyFaster(challengerScore.WeightedDelay, incumbentScore.WeightedDelay, e.switchMargin) {
		moveCandidateFirst(eligible, incumbentIndex)
		return ReasonStickyMargin, true
	}
	return "", false
}

func significantlyFaster(challenger, incumbent time.Duration, margin float64) bool {
	if incumbent <= 0 {
		return true
	}
	if challenger <= 0 {
		return false
	}
	if margin <= 0 {
		return challenger < incumbent
	}
	return float64(challenger) <= float64(incumbent)*(1-margin)
}

func weightedDelay(delay time.Duration, weight float64) time.Duration {
	if weight <= 0 {
		weight = nodeweight.Default
	}
	return time.Duration(float64(delay) / weight)
}

func modeUsesLease(mode PolicyMode) bool {
	return mode != ModeBulk && mode != ModeLatency
}

// candidatePriority combines generic endpoint health with transport- and
// service-specific evidence. A node that passes a generic URL test but fails a
// real TCP/UDP connection is therefore ranked below a proven working node.
func (e *PolicyEngine) candidatePriority(candidate Candidate, service ServiceContext) (int, time.Duration) {
	score := e.candidateScore(candidate, service)
	return score.HealthPriority, score.ObservedDelay
}

type CandidateScoreExplanation struct {
	HealthPriority   int
	ObservedDelay    time.Duration
	SmoothedDelay    time.Duration
	WeightedDelay    time.Duration
	SelectionScore   uint64
	DominantEvidence string
	ManualWeight     float64
}

func (e *PolicyEngine) candidateScore(candidate Candidate, service ServiceContext) CandidateScoreExplanation {
	type namedStatus struct {
		name   string
		status HealthStatus
	}
	statuses := []namedStatus{
		{name: "endpoint", status: e.health.EndpointHandle(candidate.Handle)},
		{name: serviceHealthTransport(service), status: e.health.StatusHandle(candidate.Handle, DomainTransport, serviceHealthTransport(service), "")},
	}
	if service.ID != "" {
		statuses = append(statuses, namedStatus{name: "service:" + service.ID, status: e.health.StatusHandle(candidate.Handle, DomainService, "", service.ID)})
	}
	priority := healthPriority(HealthHealthy)
	var delay time.Duration
	var smoothed time.Duration
	dominant := "endpoint"
	for _, item := range statuses {
		status := item.status
		if current := healthPriority(status.Health); current > priority {
			priority = current
			dominant = item.name
		}
		ranking := status.RankingDelay()
		if ranking > 0 && (delay == 0 || ranking > delay) {
			delay = ranking
		}
		if status.SmoothedDelay > 0 && (smoothed == 0 || status.SmoothedDelay > smoothed) {
			smoothed = status.SmoothedDelay
		}
	}
	if delay == 0 {
		delay = 10 * time.Second
	}
	if smoothed == 0 {
		smoothed = delay
	}
	weight := nodeweight.Default
	if e != nil && e.nodeWeights != nil {
		weight = e.nodeWeights.Weight(candidate.PrimaryTag)
	}
	weighted := weightedDelay(smoothed, weight)
	score := uint64(priority) * 1_000_000_000_000
	if weighted > 0 {
		score += uint64(weighted.Microseconds())
	}
	return CandidateScoreExplanation{
		HealthPriority:   priority,
		ObservedDelay:    delay,
		SmoothedDelay:    smoothed,
		WeightedDelay:    weighted,
		SelectionScore:   score,
		DominantEvidence: dominant,
		ManualWeight:     weight,
	}
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
	if e == nil || e.health == nil {
		return false
	}
	if !e.health.CanAttemptHandle(candidate.Handle, service, time.Time{}) {
		return true
	}
	profile := e.health.BuildCapabilityProfile(candidate.Handle, time.Time{})
	ok, _ := profile.SupportsService(service)
	return !ok
}

// ExclusionReason explains why a candidate is out of the plan for a service.
func (e *PolicyEngine) ExclusionReason(candidate Candidate, service ServiceContext) string {
	if e == nil || e.health == nil {
		return ""
	}
	if reason := e.health.ExplainExclusion(candidate.Handle, service, time.Time{}); reason != "" {
		return reason
	}
	profile := e.health.BuildCapabilityProfile(candidate.Handle, time.Time{})
	if ok, reason := profile.SupportsService(service); !ok {
		return reason
	}
	return ""
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
