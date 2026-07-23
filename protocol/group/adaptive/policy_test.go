package adaptive

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"
)

func testExecutionSnapshot(candidates ...Candidate) *ExecutionSnapshot {
	snapshot := &ExecutionSnapshot{
		Generation: 1,
		Candidates: candidates,
		ByID:       make(map[NodeID]int, len(candidates)),
		AliasToID:  make(map[string]NodeID, len(candidates)),
	}
	for index, candidate := range candidates {
		if candidate.Handle.NodeID == (NodeID{}) {
			candidate.Handle.NodeID = candidate.ID
		}
		if len(candidate.Transport) == 0 {
			candidate.Transport = []string{N.NetworkTCP, N.NetworkUDP}
		}
		candidates[index] = candidate
		snapshot.ByID[candidate.ID] = index
		snapshot.AliasToID[candidate.PrimaryTag] = candidate.ID
	}
	return snapshot
}

func TestPolicyKeepsHealthySessionLease(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	first := Candidate{ID: NodeID{1}, PrimaryTag: "first"}
	second := Candidate{ID: NodeID{2}, PrimaryTag: "second"}
	health.Observe(Observation{NodeID: first.ID, Scope: ScopeEndpoint, Outcome: OutcomeSuccess, Delay: 20 * time.Millisecond})
	health.Observe(Observation{NodeID: second.ID, Scope: ScopeEndpoint, Outcome: OutcomeSuccess, Delay: 10 * time.Millisecond})
	engine := NewPolicyEngine(health, 3, "fallback")
	service := ServiceContext{ID: "youtube", Mode: ModeStrictAffinity, Transport: N.NetworkTCP}
	lease := &SessionLease{NodeID: first.ID}
	plan, err := engine.Plan(testExecutionSnapshot(first, second), service, lease, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Reason != ReasonLease || plan.Candidates[0].ID != first.ID || len(plan.Candidates) != 1 {
		t.Fatalf("healthy lease was not retained: %+v", plan)
	}
}

func TestStrictAffinityLeaseFailsClosedInsteadOfChangingNode(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	leased := Candidate{ID: NodeID{11}, Handle: NodeHandle{NodeID: NodeID{11}, Slot: 1, Version: 1}, PrimaryTag: "leased"}
	alternative := Candidate{ID: NodeID{12}, Handle: NodeHandle{NodeID: NodeID{12}, Slot: 2, Version: 1}, PrimaryTag: "alternative"}
	for range 3 {
		health.Observe(Observation{NodeID: leased.ID, NodeSlot: leased.Handle.Slot, NodeVersion: leased.Handle.Version, Scope: DomainEndpoint, Outcome: OutcomeFailure})
	}
	service := ServiceContext{ID: "youtube", Mode: ModeStrictAffinity, Transport: N.NetworkTCP}
	lease := &SessionLease{NodeID: leased.ID, NodeSlot: leased.Handle.Slot, NodeVersion: leased.Handle.Version, ServiceID: service.ID, Mode: service.Mode}
	_, err := NewPolicyEngine(health, 3, "fallback").Plan(testExecutionSnapshot(leased, alternative), service, lease, nil)
	if err != ErrStrictAffinityUnavailable {
		t.Fatalf("strict affinity silently changed node: %v", err)
	}
}

func TestAdaptiveKeepsFallbacksWhileBulkRotatesAndIgnoresLease(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	candidates := []Candidate{
		{ID: NodeID{21}, Handle: NodeHandle{NodeID: NodeID{21}, Slot: 1, Version: 1}, PrimaryTag: "a"},
		{ID: NodeID{22}, Handle: NodeHandle{NodeID: NodeID{22}, Slot: 2, Version: 1}, PrimaryTag: "b"},
		{ID: NodeID{23}, Handle: NodeHandle{NodeID: NodeID{23}, Slot: 3, Version: 1}, PrimaryTag: "c"},
	}
	engine := NewPolicyEngine(health, 3, "fallback")
	lease := &SessionLease{NodeID: candidates[2].ID, NodeSlot: candidates[2].Handle.Slot, NodeVersion: candidates[2].Handle.Version}
	adaptiveService := ServiceContext{ID: "site:example.com", Mode: ModeAdaptive, Transport: N.NetworkTCP}
	adaptivePlan, err := engine.Plan(testExecutionSnapshot(candidates...), adaptiveService, lease, nil)
	if err != nil {
		t.Fatal(err)
	}
	if adaptivePlan.Reason != ReasonLease || adaptivePlan.Candidates[0].ID != lease.NodeID || len(adaptivePlan.Candidates) != 3 {
		t.Fatalf("adaptive mode lost lease-first fallback behavior: %+v", adaptivePlan)
	}
	bulkService := ServiceContext{ID: "site:example.com", Mode: ModeBulk, Transport: N.NetworkTCP}
	want := []NodeID{candidates[0].ID, candidates[1].ID, candidates[2].ID, candidates[0].ID}
	for index, expected := range want {
		plan, planErr := engine.Plan(testExecutionSnapshot(candidates...), bulkService, lease, nil)
		if planErr != nil {
			t.Fatal(planErr)
		}
		if plan.Reason != ReasonBulkSpread || plan.Candidates[0].ID != expected {
			t.Fatalf("bulk connection %d did not rotate independently of lease: %+v", index, plan)
		}
	}
}

func TestPolicyManualPinFallbackIsExplicit(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	pinned := Candidate{ID: NodeID{1}, PrimaryTag: "pinned"}
	fallback := Candidate{ID: NodeID{2}, PrimaryTag: "fallback"}
	for range 3 {
		health.Observe(Observation{NodeID: pinned.ID, Scope: ScopeEndpoint, Outcome: OutcomeFailure})
	}
	health.Observe(Observation{NodeID: fallback.ID, Scope: ScopeEndpoint, Outcome: OutcomeSuccess})
	engine := NewPolicyEngine(health, 3, "fallback")
	service := ServiceContext{ID: "site:example.com", Mode: ModeAdaptive, Transport: N.NetworkTCP}
	pin := pinned.ID
	plan, err := engine.Plan(testExecutionSnapshot(pinned, fallback), service, nil, &pin)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Reason != ReasonFallback || plan.Candidates[0].ID != fallback.ID {
		t.Fatalf("manual fallback was not explicit: %+v", plan)
	}
}

func TestAdaptivePoolDisablesPreMatchLeafSelection(t *testing.T) {
	pool := new(AdaptivePool)
	if _, loaded := any(pool).(adapter.PreMatchOutboundGroup); loaded {
		t.Fatal("adaptive pool still implements pre-match leaf selection")
	}
	if _, loaded := any(pool).(adapter.PreMatchDisabledOutbound); !loaded {
		t.Fatal("adaptive pool does not disable pre-match")
	}
}

func TestServiceFailureDoesNotOpenEndpointBreaker(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	first := Candidate{ID: NodeID{1}, PrimaryTag: "first"}
	second := Candidate{ID: NodeID{2}, PrimaryTag: "second"}
	for range 3 {
		health.Observe(Observation{NodeID: first.ID, Scope: ScopeService, Service: "youtube", Outcome: OutcomeFailure})
	}
	engine := NewPolicyEngine(health, 3, "fallback")
	youtube := ServiceContext{ID: "youtube", Mode: ModeStrictAffinity, Transport: N.NetworkTCP}
	plan, err := engine.Plan(testExecutionSnapshot(first, second), youtube, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Candidates[0].ID != second.ID {
		t.Fatalf("service breaker did not exclude failed candidate: %+v", plan)
	}
	ordinary := ServiceContext{ID: "site:example.com", Mode: ModeAdaptive, Transport: N.NetworkTCP}
	plan, err = engine.Plan(testExecutionSnapshot(first, second), ordinary, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Candidates[0].ID != first.ID {
		t.Fatalf("service failure contaminated unrelated endpoint ranking: %+v", plan)
	}
}

func TestPolicyClosedUnknownIsNotHealthyAndDegradedDoesNotBeatSuccess(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	degraded := Candidate{ID: NodeID{1}, PrimaryTag: "degraded"}
	healthy := Candidate{ID: NodeID{2}, PrimaryTag: "healthy"}
	unknown := Candidate{ID: NodeID{3}, PrimaryTag: "unknown"}
	health.Observe(Observation{NodeID: degraded.ID, Scope: DomainEndpoint, Outcome: OutcomeFailure, Delay: time.Millisecond})
	health.Observe(Observation{NodeID: healthy.ID, Scope: DomainEndpoint, Outcome: OutcomeSuccess, Delay: 50 * time.Millisecond})
	engine := NewPolicyEngine(health, 3, "fallback")
	service := ServiceContext{ID: "service", Mode: ModeAdaptive, Transport: N.NetworkTCP}
	plan, err := engine.Plan(testExecutionSnapshot(degraded, unknown, healthy), service, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Candidates[0].ID != healthy.ID || plan.Candidates[1].ID != unknown.ID || plan.Candidates[2].ID != degraded.ID {
		t.Fatalf("health evidence ordering is wrong: %v", []string{plan.Candidates[0].PrimaryTag, plan.Candidates[1].PrimaryTag, plan.Candidates[2].PrimaryTag})
	}
	if status := health.Endpoint(unknown.ID); status.Health != HealthUnknown || status.Breaker != BreakerClosed {
		t.Fatalf("closed unknown was presented as healthy: %+v", status)
	}
}

func TestPolicyReaddedVersionDoesNotInheritBreakerOrLease(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	nodeID := NodeID{44}
	for range 3 {
		health.Observe(Observation{NodeID: nodeID, NodeSlot: 1, NodeVersion: 1, Scope: DomainEndpoint, Outcome: OutcomeFailure})
	}
	candidate := Candidate{ID: nodeID, Handle: NodeHandle{NodeID: nodeID, Slot: 1, Version: 2, BornRevision: 2}, PrimaryTag: "readded"}
	service := ServiceContext{ID: "service", Mode: ModeAdaptive, Transport: N.NetworkTCP}
	oldLease := &SessionLease{NodeID: nodeID, NodeSlot: 1, NodeVersion: 1, ServiceID: service.ID, Mode: ModeAdaptive}
	plan, err := NewPolicyEngine(health, 1, "fallback").Plan(testExecutionSnapshot(candidate), service, oldLease, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Reason == ReasonLease || len(plan.Candidates) != 1 || plan.Candidates[0].Handle.Version != 2 {
		t.Fatalf("v1 lease/breaker contaminated v2 plan: %+v", plan)
	}
	if status := health.EndpointHandle(candidate.Handle); status.Health != HealthUnknown || status.Breaker != BreakerClosed {
		t.Fatalf("v2 did not start with isolated health: %+v", status)
	}
}

func TestBulkPolicyExploitsThroughputAndPeriodicallyExplores(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	fast := Candidate{ID: NodeID{51}, Handle: NodeHandle{NodeID: NodeID{51}, Slot: 1, Version: 1}, PrimaryTag: "fast"}
	slow := Candidate{ID: NodeID{52}, Handle: NodeHandle{NodeID: NodeID{52}, Slot: 2, Version: 1}, PrimaryTag: "slow"}
	unknown := Candidate{ID: NodeID{53}, Handle: NodeHandle{NodeID: NodeID{53}, Slot: 3, Version: 1}, PrimaryTag: "unknown"}
	service := ServiceContext{ID: "bulk-service", Mode: ModeBulk, Transport: N.NetworkTCP}
	for range 2 {
		health.ObserveEvidence(Observation{NodeID: fast.ID, NodeSlot: fast.Handle.Slot, NodeVersion: fast.Handle.Version, Scope: DomainService, Service: service.ID, Outcome: OutcomeSuccess, ThroughputBPS: 8 << 20}, false, 0.6)
		health.ObserveEvidence(Observation{NodeID: slow.ID, NodeSlot: slow.Handle.Slot, NodeVersion: slow.Handle.Version, Scope: DomainService, Service: service.ID, Outcome: OutcomeSuccess, ThroughputBPS: 1 << 20}, false, 0.6)
	}
	sequence := new(atomic.Uint64)
	engine := NewPolicyEngine(health, 3, "fallback").BindBulkSequence(sequence)
	plan, err := engine.Plan(testExecutionSnapshot(slow, unknown, fast), service, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Reason != ReasonBulkThroughput || plan.Candidates[0].ID != fast.ID {
		t.Fatalf("bulk policy did not exploit trusted throughput: %+v", plan)
	}
	sequence.Store(9)
	plan, err = engine.Plan(testExecutionSnapshot(slow, unknown, fast), service, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Reason != ReasonBulkSpread || plan.Candidates[0].ID != unknown.ID {
		t.Fatalf("bulk policy starved unknown candidate instead of exploring: %+v", plan)
	}
}
