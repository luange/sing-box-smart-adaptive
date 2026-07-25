package adaptive

import (
	"container/list"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// FailureDomain is deliberately independent from the observation source. A
// later observation contract can map dial, TLS, HTTP and UDP evidence into
// these domains without changing breaker state management.
type FailureDomain string

const (
	DomainEndpoint  FailureDomain = "endpoint"
	DomainTransport FailureDomain = "transport"
	DomainService   FailureDomain = "service"
)

// ObservationScope is retained as a source-compatible name for existing
// callers; new code should use FailureDomain/Domain*.
type ObservationScope = FailureDomain

const (
	ScopeEndpoint  = DomainEndpoint
	ScopeTransport = DomainTransport
	ScopeService   = DomainService
)

type ObservationOutcome string

const (
	OutcomeSuccess  ObservationOutcome = "success"
	OutcomeFailure  ObservationOutcome = "failure"
	OutcomeBlocked  ObservationOutcome = "blocked"
	OutcomeDeferred ObservationOutcome = "deferred"
)

type BreakerState string

const (
	BreakerUnknown  BreakerState = "unknown"
	BreakerClosed   BreakerState = "closed"
	BreakerOpen     BreakerState = "open"
	BreakerCooldown BreakerState = "cooldown"
	BreakerHalfOpen BreakerState = "half_open"
)

type HealthState string

const (
	HealthUnknown     HealthState = "unknown"
	HealthHealthy     HealthState = "healthy"
	HealthDegraded    HealthState = "degraded"
	HealthUnreachable HealthState = "unreachable"
)

type Observation struct {
	NodeID        NodeID
	NodeSlot      uint64
	NodeVersion   uint64
	Scope         FailureDomain
	Transport     string
	Service       string
	Outcome       ObservationOutcome
	Delay         time.Duration
	ThroughputBPS float64
	At            time.Time
	Reason        string
}

type HealthStatus struct {
	Health              HealthState
	Breaker             BreakerState
	LastUpdated         time.Time
	LastDelay           time.Duration
	ThroughputBPS       float64
	ThroughputSamples   uint64
	Successes           uint64
	Failures            uint64
	NonBreakerSuccesses uint64
	NonBreakerFailures  uint64
	EvidenceWeight      float64
	ConsecutiveFailures int
	CooldownUntil       time.Time
	Backoff             time.Duration
	HalfOpen            bool
	Reason              string
}

type ThroughputSummary struct {
	BPS       float64
	Samples   uint64
	UpdatedAt time.Time
}

type healthKey struct {
	nodeID      NodeID
	nodeSlot    uint64
	nodeVersion uint64
	domain      FailureDomain
	transport   string
	service     string
}

type healthRecord struct {
	key                healthKey
	status             HealthStatus
	consecutiveFailure int
	reopenCount        int
	openUntil          time.Time
	halfOpenToken      uint64
	version            uint64
	element            *list.Element
}

type Clock interface{ Now() time.Time }

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

type BreakerConfig struct {
	FailureThreshold int
	BaseCooldown     time.Duration
	MaxCooldown      time.Duration
}

func defaultBreakerConfig() BreakerConfig {
	return BreakerConfig{FailureThreshold: 3, BaseCooldown: 5 * time.Second, MaxCooldown: 5 * time.Minute}
}

// AttemptPermit owns only half-open tokens actually acquired by an attempt.
// Closed breakers do not need a token. CompleteDomains is idempotent and must
// be called exactly once by the attempt owner; ReleaseDeferred is for
// cancellation before an outcome exists and never increments failure counters.
type AttemptPermit struct {
	store     *HealthStore
	entries   []permitEntry
	completed atomic.Bool
}

type permitEntry struct {
	key           healthKey
	version       uint64
	halfOpenToken uint64
}

func (p *AttemptPermit) CompleteDomains(outcomes map[FailureDomain]ObservationOutcome, at time.Time, delay time.Duration, reason string) {
	if p == nil || p.store == nil || !p.completed.CompareAndSwap(false, true) {
		return
	}
	p.store.completePermitDomains(p.entries, outcomes, at, delay, reason)
}

func (p *AttemptPermit) ReleaseDeferred() {
	if p == nil || p.store == nil || !p.completed.CompareAndSwap(false, true) {
		return
	}
	p.store.releasePermit(p.entries)
}

type HealthStore struct {
	access     sync.RWMutex
	entries    map[healthKey]*healthRecord
	lru        list.List
	retention  time.Duration
	maxEntries int
	evictions  uint64
	clock      Clock
	breaker    BreakerConfig
	nextToken  uint64
}

func (s *HealthStore) PersistenceSnapshot() []persistedHealthRecord {
	s.access.RLock()
	defer s.access.RUnlock()
	result := make([]persistedHealthRecord, 0, len(s.entries))
	for _, record := range s.entries {
		result = append(result, persistedHealthRecord{
			NodeID: record.key.nodeID, NodeSlot: record.key.nodeSlot, NodeVersion: record.key.nodeVersion,
			Domain: record.key.domain, Transport: record.key.transport, Service: record.key.service,
			Health: record.status.Health, Breaker: record.status.Breaker, LastUpdated: record.status.LastUpdated,
			LastDelay: record.status.LastDelay, Successes: record.status.Successes, Failures: record.status.Failures,
			ThroughputBPS: record.status.ThroughputBPS, ThroughputSamples: record.status.ThroughputSamples,
			NonBreakerSuccesses: record.status.NonBreakerSuccesses, NonBreakerFailures: record.status.NonBreakerFailures,
			EvidenceWeight: record.status.EvidenceWeight, ConsecutiveFailures: record.consecutiveFailure,
			OpenUntil: record.openUntil, Backoff: record.status.Backoff, ReopenCount: record.reopenCount,
		})
	}
	return result
}

func (s *HealthStore) RestorePersistence(records []persistedHealthRecord, now time.Time) {
	s.access.Lock()
	defer s.access.Unlock()
	for _, persisted := range records {
		if persisted.NodeID == (NodeID{}) || persisted.NodeSlot == 0 || persisted.NodeVersion == 0 || persisted.LastUpdated.IsZero() || now.Sub(persisted.LastUpdated) > s.retention || persisted.LastUpdated.After(now.Add(time.Minute)) {
			continue
		}
		key := healthKey{nodeID: persisted.NodeID, nodeSlot: persisted.NodeSlot, nodeVersion: persisted.NodeVersion, domain: persisted.Domain, transport: persisted.Transport, service: persisted.Service}
		if _, exists := s.entries[key]; exists {
			continue
		}
		status := HealthStatus{Health: persisted.Health, Breaker: persisted.Breaker, LastUpdated: persisted.LastUpdated, LastDelay: persisted.LastDelay, ThroughputBPS: persisted.ThroughputBPS, ThroughputSamples: persisted.ThroughputSamples, Successes: persisted.Successes, Failures: persisted.Failures, NonBreakerSuccesses: persisted.NonBreakerSuccesses, NonBreakerFailures: persisted.NonBreakerFailures, EvidenceWeight: persisted.EvidenceWeight, ConsecutiveFailures: persisted.ConsecutiveFailures, Backoff: persisted.Backoff, Reason: "restored"}
		openUntil := persisted.OpenUntil
		if status.Breaker == BreakerHalfOpen {
			status.Breaker = BreakerClosed
			openUntil = time.Time{}
		}
		if !openUntil.IsZero() && !openUntil.After(now) {
			status.Breaker = BreakerClosed
			openUntil = time.Time{}
			status.CooldownUntil = time.Time{}
		}
		if status.Breaker != BreakerOpen && status.Breaker != BreakerCooldown {
			status.Breaker = BreakerClosed
		}
		if !openUntil.IsZero() {
			status.CooldownUntil = openUntil
		}
		record := &healthRecord{key: key, status: status, consecutiveFailure: persisted.ConsecutiveFailures, reopenCount: persisted.ReopenCount, openUntil: openUntil}
		record.element = s.lru.PushFront(record)
		s.entries[key] = record
	}
	for len(s.entries) > s.maxEntries {
		s.removeOldestLocked()
	}
}

func NewHealthStore(retention time.Duration, maxEntries int) *HealthStore {
	return NewHealthStoreWithClock(retention, maxEntries, realClock{}, defaultBreakerConfig())
}

func NewHealthStoreWithClock(retention time.Duration, maxEntries int, clock Clock, breaker BreakerConfig) *HealthStore {
	if retention <= 0 {
		retention = 7 * 24 * time.Hour
	}
	if maxEntries <= 0 {
		maxEntries = 4096
	}
	if clock == nil {
		clock = realClock{}
	}
	defaults := defaultBreakerConfig()
	if breaker.FailureThreshold <= 0 {
		breaker.FailureThreshold = defaults.FailureThreshold
	}
	if breaker.BaseCooldown <= 0 {
		breaker.BaseCooldown = defaults.BaseCooldown
	}
	if breaker.MaxCooldown < breaker.BaseCooldown {
		breaker.MaxCooldown = defaults.MaxCooldown
	}
	return &HealthStore{entries: make(map[healthKey]*healthRecord), retention: retention, maxEntries: maxEntries, clock: clock, breaker: breaker}
}

func (s *HealthStore) Observe(observation Observation) {
	s.ObserveEvidence(observation, true, 1)
}

func (s *HealthStore) ThroughputByHandle() map[NodeHandle]ThroughputSummary {
	s.access.RLock()
	defer s.access.RUnlock()
	type aggregate struct {
		weightedLog float64
		samples     uint64
		updatedAt   time.Time
	}
	aggregates := make(map[NodeHandle]aggregate)
	for _, record := range s.entries {
		if record.key.domain != DomainService || record.status.ThroughputSamples == 0 || record.status.ThroughputBPS <= 0 {
			continue
		}
		handle := NodeHandle{NodeID: record.key.nodeID, Slot: record.key.nodeSlot, Version: record.key.nodeVersion}
		current := aggregates[handle]
		current.weightedLog += math.Log1p(record.status.ThroughputBPS) * float64(record.status.ThroughputSamples)
		current.samples += record.status.ThroughputSamples
		if record.status.LastUpdated.After(current.updatedAt) {
			current.updatedAt = record.status.LastUpdated
		}
		aggregates[handle] = current
	}
	result := make(map[NodeHandle]ThroughputSummary, len(aggregates))
	for handle, aggregate := range aggregates {
		result[handle] = ThroughputSummary{BPS: math.Expm1(aggregate.weightedLog / float64(aggregate.samples)), Samples: aggregate.samples, UpdatedAt: aggregate.updatedAt}
	}
	return result
}

func (s *HealthStore) ObserveEvidence(observation Observation, breakerEligible bool, weight float64) {
	if observation.Outcome == OutcomeDeferred {
		return
	}
	if observation.At.IsZero() {
		observation.At = s.clock.Now()
	}
	s.access.Lock()
	key := healthKey{nodeID: observation.NodeID, nodeSlot: observation.NodeSlot, nodeVersion: observation.NodeVersion, domain: observation.Scope, transport: observation.Transport, service: observation.Service}
	if breakerEligible {
		s.observeLocked(key, observation.Outcome, observation.At, observation.Delay, observation.Reason, 0, 0, false)
	} else {
		s.observeQualityLocked(key, observation, weight)
	}
	s.access.Unlock()
}

func (s *HealthStore) observeQualityLocked(key healthKey, observation Observation, weight float64) {
	s.pruneExpiredLocked(observation.At)
	record := s.entries[key]
	if record != nil && !record.status.LastUpdated.IsZero() && observation.At.Before(record.status.LastUpdated) {
		return
	}
	if record == nil {
		record = &healthRecord{key: key}
		record.status.Breaker = BreakerClosed
		record.element = s.lru.PushFront(record)
		s.entries[key] = record
	} else {
		s.lru.MoveToFront(record.element)
	}
	if weight < 0 {
		weight = 0
	}
	record.status.LastUpdated = observation.At
	record.status.Reason = observation.Reason
	record.status.EvidenceWeight += weight
	if observation.Delay > 0 {
		record.status.LastDelay = observation.Delay
	}
	if observation.ThroughputBPS > 0 && !math.IsNaN(observation.ThroughputBPS) && !math.IsInf(observation.ThroughputBPS, 0) {
		logValue := math.Log1p(observation.ThroughputBPS)
		if record.status.ThroughputSamples == 0 || record.status.ThroughputBPS <= 0 {
			record.status.ThroughputBPS = observation.ThroughputBPS
		} else {
			window := min(float64(record.status.ThroughputSamples+1), 8)
			current := math.Log1p(record.status.ThroughputBPS)
			record.status.ThroughputBPS = math.Expm1(current + (logValue-current)/window)
		}
		record.status.ThroughputSamples++
	}
	if observation.Outcome == OutcomeSuccess {
		record.status.NonBreakerSuccesses++
		if record.status.Breaker == BreakerClosed && record.status.Health != HealthUnreachable {
			record.status.Health = HealthHealthy
		}
	} else {
		record.status.NonBreakerFailures++
		if record.status.Breaker == BreakerClosed && record.status.Health != HealthUnreachable {
			record.status.Health = HealthDegraded
		}
	}
	for len(s.entries) > s.maxEntries {
		s.removeOldestLocked()
	}
}

// TryAcquireAttemptPermit atomically acquires all required domains. The order
// is fixed so concurrent attempts cannot deadlock or partially reserve a node.
func (s *HealthStore) TryAcquireAttemptPermit(nodeID NodeID, service ServiceContext, at time.Time) (*AttemptPermit, bool) {
	return s.TryAcquireAttemptPermitVersion(nodeID, 0, service, at)
}

func (s *HealthStore) TryAcquireAttemptPermitVersion(nodeID NodeID, nodeVersion uint64, service ServiceContext, at time.Time) (*AttemptPermit, bool) {
	return s.TryAcquireAttemptPermitHandle(NodeHandle{NodeID: nodeID, Version: nodeVersion}, service, at)
}

func (s *HealthStore) TryAcquireAttemptPermitHandle(handle NodeHandle, service ServiceContext, at time.Time) (*AttemptPermit, bool) {
	if at.IsZero() {
		at = s.clock.Now()
	}
	keys := []healthKey{{nodeID: handle.NodeID, nodeSlot: handle.Slot, nodeVersion: handle.Version, domain: DomainEndpoint}, {nodeID: handle.NodeID, nodeSlot: handle.Slot, nodeVersion: handle.Version, domain: DomainTransport, transport: service.Transport}, {nodeID: handle.NodeID, nodeSlot: handle.Slot, nodeVersion: handle.Version, domain: DomainService, service: service.ID}}
	return s.tryAcquirePermit(keys, at)
}

// TryAcquireConnectionPermitHandle deliberately excludes the service domain.
// A service half-open token is acquired only after the first payload exists.
func (s *HealthStore) TryAcquireConnectionPermitHandle(handle NodeHandle, transport string, at time.Time) (*AttemptPermit, bool) {
	if at.IsZero() {
		at = s.clock.Now()
	}
	keys := []healthKey{{nodeID: handle.NodeID, nodeSlot: handle.Slot, nodeVersion: handle.Version, domain: DomainEndpoint}, {nodeID: handle.NodeID, nodeSlot: handle.Slot, nodeVersion: handle.Version, domain: DomainTransport, transport: transport}}
	return s.tryAcquirePermit(keys, at)
}

// TryAcquireConnectionFallbackPermitHandle permits one bounded last-resort
// attempt when policy has no normally eligible candidate. It preserves the
// captured record versions so a successful attempt can close an open breaker,
// but never competes with an existing half-open owner.
func (s *HealthStore) TryAcquireConnectionFallbackPermitHandle(handle NodeHandle, transport string, at time.Time) (*AttemptPermit, bool) {
	if at.IsZero() {
		at = s.clock.Now()
	}
	keys := []healthKey{{nodeID: handle.NodeID, nodeSlot: handle.Slot, nodeVersion: handle.Version, domain: DomainEndpoint}, {nodeID: handle.NodeID, nodeSlot: handle.Slot, nodeVersion: handle.Version, domain: DomainTransport, transport: transport}}
	s.access.Lock()
	defer s.access.Unlock()
	entries := make([]permitEntry, 0, len(keys))
	for _, key := range keys {
		record := s.entries[key]
		if record == nil {
			entries = append(entries, permitEntry{key: key})
			continue
		}
		if record.status.Breaker == BreakerHalfOpen {
			return nil, false
		}
		entries = append(entries, permitEntry{key: key, version: record.version})
	}
	return &AttemptPermit{store: s, entries: entries}, true
}

func (s *HealthStore) tryAcquirePermit(keys []healthKey, at time.Time) (*AttemptPermit, bool) {
	s.access.Lock()
	defer s.access.Unlock()
	entries := make([]permitEntry, 0, len(keys))
	for _, key := range keys {
		record := s.entries[key]
		if record == nil {
			entries = append(entries, permitEntry{key: key})
			continue
		}
		if !s.availableLocked(record, at) {
			for _, entry := range entries {
				s.releaseTokenLocked(entry)
			}
			return nil, false
		}
		if record.status.Breaker == BreakerOpen || record.status.Breaker == BreakerCooldown {
			record.status.Breaker = BreakerHalfOpen
			record.status.HalfOpen = true
			s.nextToken++
			record.halfOpenToken = s.nextToken
			entries = append(entries, permitEntry{key: key, version: record.version, halfOpenToken: record.halfOpenToken})
		} else {
			entries = append(entries, permitEntry{key: key, version: record.version})
		}
	}
	return &AttemptPermit{store: s, entries: entries}, true
}

func (s *HealthStore) TryAcquireDomainPermit(nodeID NodeID, domain FailureDomain, transport, service string, at time.Time) (*AttemptPermit, bool) {
	return s.TryAcquireDomainPermitVersion(nodeID, 0, domain, transport, service, at)
}

func (s *HealthStore) TryAcquireDomainPermitVersion(nodeID NodeID, nodeVersion uint64, domain FailureDomain, transport, service string, at time.Time) (*AttemptPermit, bool) {
	return s.TryAcquireDomainPermitHandle(NodeHandle{NodeID: nodeID, Version: nodeVersion}, domain, transport, service, at)
}

func (s *HealthStore) TryAcquireDomainPermitHandle(handle NodeHandle, domain FailureDomain, transport, service string, at time.Time) (*AttemptPermit, bool) {
	if at.IsZero() {
		at = s.clock.Now()
	}
	key := healthKey{nodeID: handle.NodeID, nodeSlot: handle.Slot, nodeVersion: handle.Version, domain: domain, transport: transport, service: service}
	s.access.Lock()
	defer s.access.Unlock()
	record := s.entries[key]
	if record == nil {
		return &AttemptPermit{store: s, entries: []permitEntry{{key: key}}}, true
	}
	if !s.availableLocked(record, at) {
		return nil, false
	}
	entry := permitEntry{key: key, version: record.version}
	if record.status.Breaker == BreakerOpen || record.status.Breaker == BreakerCooldown {
		record.status.Breaker = BreakerHalfOpen
		record.status.HalfOpen = true
		s.nextToken++
		record.halfOpenToken = s.nextToken
		entry.halfOpenToken = record.halfOpenToken
	}
	return &AttemptPermit{store: s, entries: []permitEntry{entry}}, true
}

func (s *HealthStore) CanAttempt(nodeID NodeID, service ServiceContext, at time.Time) bool {
	return s.CanAttemptVersion(nodeID, 0, service, at)
}

func (s *HealthStore) CanAttemptVersion(nodeID NodeID, nodeVersion uint64, service ServiceContext, at time.Time) bool {
	return s.CanAttemptHandle(NodeHandle{NodeID: nodeID, Version: nodeVersion}, service, at)
}

func (s *HealthStore) CanAttemptHandle(handle NodeHandle, service ServiceContext, at time.Time) bool {
	if at.IsZero() {
		at = s.clock.Now()
	}
	keys := []healthKey{{nodeID: handle.NodeID, nodeSlot: handle.Slot, nodeVersion: handle.Version, domain: DomainEndpoint}, {nodeID: handle.NodeID, nodeSlot: handle.Slot, nodeVersion: handle.Version, domain: DomainTransport, transport: service.Transport}, {nodeID: handle.NodeID, nodeSlot: handle.Slot, nodeVersion: handle.Version, domain: DomainService, service: service.ID}}
	s.access.Lock()
	defer s.access.Unlock()
	for _, key := range keys {
		if record := s.entries[key]; record != nil && !s.availableLocked(record, at) {
			return false
		}
	}
	return true
}

func (s *HealthStore) availableLocked(record *healthRecord, now time.Time) bool {
	switch record.status.Breaker {
	case BreakerOpen:
		if now.Before(record.openUntil) {
			record.status.Breaker = BreakerCooldown
			record.status.CooldownUntil = record.openUntil
			return false
		}
		return true
	case BreakerCooldown:
		return !now.Before(record.openUntil)
	case BreakerHalfOpen:
		return false
	default:
		return true
	}
}

func (s *HealthStore) completePermitDomains(entries []permitEntry, outcomes map[FailureDomain]ObservationOutcome, at time.Time, delay time.Duration, reason string) {
	if at.IsZero() {
		at = s.clock.Now()
	}
	s.access.Lock()
	for _, entry := range entries {
		outcome, loaded := outcomes[entry.key.domain]
		if !loaded || outcome == OutcomeDeferred {
			s.releaseTokenLocked(entry)
			continue
		}
		s.observeLocked(entry.key, outcome, at, delay, reason, entry.version, entry.halfOpenToken, true)
	}
	s.access.Unlock()
}

func (s *HealthStore) releasePermit(entries []permitEntry) {
	s.access.Lock()
	for _, entry := range entries {
		s.releaseTokenLocked(entry)
	}
	s.access.Unlock()
}

func (s *HealthStore) releaseTokenLocked(entry permitEntry) {
	if record := s.entries[entry.key]; record != nil && record.version == entry.version && record.halfOpenToken == entry.halfOpenToken && entry.halfOpenToken != 0 && record.status.Breaker == BreakerHalfOpen {
		record.status.Breaker = BreakerCooldown
		record.status.HalfOpen = false
		record.status.CooldownUntil = record.openUntil
		record.halfOpenToken = 0
	}
}

func (s *HealthStore) observeLocked(key healthKey, outcome ObservationOutcome, at time.Time, delay time.Duration, reason string, version, halfOpenToken uint64, active bool) {
	s.pruneExpiredLocked(at)
	record := s.entries[key]
	if record != nil && !record.status.LastUpdated.IsZero() && at.Before(record.status.LastUpdated) {
		return
	}
	if record == nil {
		if active && version != 0 {
			return
		}
		record = &healthRecord{key: key}
		record.element = s.lru.PushFront(record)
		s.entries[key] = record
	} else {
		s.lru.MoveToFront(record.element)
	}
	if active && record.version != version {
		return
	}
	// Passive observations can build evidence while closed, but cannot recover
	// an open breaker. Active recovery requires both the captured version and
	// the unique half-open owner token.
	if !active && record.status.Breaker != BreakerClosed && record.status.Breaker != "" {
		return
	}
	if record.status.Breaker == BreakerHalfOpen && halfOpenToken != record.halfOpenToken {
		return
	}
	record.status.LastUpdated = at
	record.status.Reason = reason
	if delay > 0 {
		record.status.LastDelay = delay
	}
	if outcome == OutcomeSuccess {
		record.status.Successes++
		record.consecutiveFailure = 0
		record.reopenCount = 0
		record.openUntil = time.Time{}
		record.halfOpenToken = 0
		record.status.Health = HealthHealthy
		record.status.Breaker = BreakerClosed
		record.status.HalfOpen = false
		record.status.CooldownUntil = time.Time{}
		record.status.Backoff = 0
	} else {
		record.status.Failures++
		record.consecutiveFailure++
		if record.status.Breaker == BreakerHalfOpen || record.consecutiveFailure >= s.breaker.FailureThreshold {
			record.status.Health = HealthUnreachable
			record.reopenCount++
			s.openBreakerRecordLocked(record, at)
		} else {
			record.status.Health = HealthDegraded
			record.status.Breaker = BreakerClosed
		}
	}
	record.status.ConsecutiveFailures = record.consecutiveFailure
	for len(s.entries) > s.maxEntries {
		s.removeOldestLocked()
	}
}

func (s *HealthStore) openBreakerRecordLocked(record *healthRecord, now time.Time) {
	backoff := s.breaker.BaseCooldown
	for i := 1; i < record.reopenCount; i++ {
		if backoff >= s.breaker.MaxCooldown/2 {
			backoff = s.breaker.MaxCooldown
			break
		}
		backoff *= 2
	}
	if backoff > s.breaker.MaxCooldown {
		backoff = s.breaker.MaxCooldown
	}
	record.openUntil = now.Add(backoff)
	record.version++
	record.status.Breaker = BreakerOpen
	record.status.HalfOpen = false
	record.status.CooldownUntil = record.openUntil
	record.status.Backoff = backoff
	record.halfOpenToken = 0
}

func (s *HealthStore) Endpoint(nodeID NodeID) HealthStatus {
	return s.Status(nodeID, DomainEndpoint, "", "")
}

func (s *HealthStore) EndpointVersion(nodeID NodeID, nodeVersion uint64) HealthStatus {
	return s.StatusVersion(nodeID, nodeVersion, DomainEndpoint, "", "")
}

func (s *HealthStore) EndpointHandle(handle NodeHandle) HealthStatus {
	return s.StatusHandle(handle, DomainEndpoint, "", "")
}

func (s *HealthStore) Status(nodeID NodeID, domain FailureDomain, transport, service string) HealthStatus {
	return s.StatusVersion(nodeID, 0, domain, transport, service)
}

func (s *HealthStore) StatusVersion(nodeID NodeID, nodeVersion uint64, domain FailureDomain, transport, service string) HealthStatus {
	return s.StatusHandle(NodeHandle{NodeID: nodeID, Version: nodeVersion}, domain, transport, service)
}

func (s *HealthStore) StatusHandle(handle NodeHandle, domain FailureDomain, transport, service string) HealthStatus {
	s.access.RLock()
	defer s.access.RUnlock()
	record := s.entries[healthKey{nodeID: handle.NodeID, nodeSlot: handle.Slot, nodeVersion: handle.Version, domain: domain, transport: transport, service: service}]
	if record == nil {
		return HealthStatus{Health: HealthUnknown, Breaker: BreakerClosed}
	}
	return record.status
}

func (s *HealthStore) RetireNodeVersion(nodeID NodeID, nodeVersion uint64) {
	s.RetireNodeHandle(NodeHandle{NodeID: nodeID, Version: nodeVersion})
}

func (s *HealthStore) RetireNodeHandle(handle NodeHandle) {
	s.access.Lock()
	for key, record := range s.entries {
		if key.nodeID == handle.NodeID && key.nodeSlot == handle.Slot && key.nodeVersion == handle.Version {
			s.removeLocked(record)
		}
	}
	s.access.Unlock()
}

func (s *HealthStore) Stats() (entries int, evictions uint64) {
	s.access.RLock()
	entries = len(s.entries)
	evictions = s.evictions
	s.access.RUnlock()
	return
}

func (s *HealthStore) pruneExpiredLocked(now time.Time) {
	for element := s.lru.Back(); element != nil; {
		previous := element.Prev()
		record := element.Value.(*healthRecord)
		if now.Sub(record.status.LastUpdated) <= s.retention {
			break
		}
		s.removeLocked(record)
		element = previous
	}
}

func (s *HealthStore) removeOldestLocked() {
	if element := s.lru.Back(); element != nil {
		s.removeLocked(element.Value.(*healthRecord))
	}
}

func (s *HealthStore) removeLocked(record *healthRecord) {
	delete(s.entries, record.key)
	s.lru.Remove(record.element)
	s.evictions++
}
