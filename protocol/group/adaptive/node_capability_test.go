package adaptive

import (
	"testing"
	"time"

	N "github.com/sagernet/sing/common/network"
)

func TestCapabilityProfileIsolatesUDPFamilies(t *testing.T) {
	store, clock := newBreakerTestStore()
	handle := NodeHandle{NodeID: NodeID{201}, Slot: 1, Version: 1}
	for range 3 {
		store.Observe(Observation{
			NodeID: handle.NodeID, NodeSlot: handle.Slot, NodeVersion: handle.Version,
			Scope: DomainTransport, Transport: "udp_dns/ipv4", Outcome: OutcomeFailure, At: clock.Now(),
		})
	}
	profile := store.BuildCapabilityProfile(handle, clock.Now())
	if profile.DNSUDPv4.Available || !profile.DNSUDPv4.Known {
		t.Fatalf("DNS UDP/IPv4 should be known-unavailable: %+v", profile.DNSUDPv4)
	}
	if !profile.DataUDPv4.Available {
		t.Fatalf("Data UDP/IPv4 contaminated by DNS failure: %+v", profile.DataUDPv4)
	}
	if !profile.TCP4.Available {
		t.Fatalf("TCP/IPv4 contaminated by DNS failure: %+v", profile.TCP4)
	}
	ok, reason := profile.SupportsService(ServiceContext{Transport: N.NetworkUDP, HealthTransport: "udp_dns/ipv4"})
	if ok || reason == "" {
		t.Fatalf("profile should reject DNS UDP service: ok=%v reason=%q", ok, reason)
	}
	ok, reason = profile.SupportsService(ServiceContext{Transport: N.NetworkUDP, HealthTransport: "udp_data/ipv4"})
	if !ok || reason != "" {
		t.Fatalf("profile should allow data UDP service: ok=%v reason=%q", ok, reason)
	}
}

func TestPolicyExcludesBrokenPathUsingCapabilityProfile(t *testing.T) {
	health := NewHealthStoreWithClock(time.Hour, 32, realClock{}, BreakerConfig{FailureThreshold: 1, BaseCooldown: time.Minute, MaxCooldown: time.Minute, JitterFraction: 0})
	good := Candidate{ID: NodeID{211}, Handle: NodeHandle{NodeID: NodeID{211}, Slot: 1, Version: 1}, PrimaryTag: "good"}
	bad := Candidate{ID: NodeID{212}, Handle: NodeHandle{NodeID: NodeID{212}, Slot: 2, Version: 1}, PrimaryTag: "bad-dns"}
	health.Observe(Observation{NodeID: good.ID, NodeSlot: 1, NodeVersion: 1, Scope: DomainEndpoint, Outcome: OutcomeSuccess, Delay: 40 * time.Millisecond})
	health.Observe(Observation{NodeID: bad.ID, NodeSlot: 2, NodeVersion: 1, Scope: DomainEndpoint, Outcome: OutcomeSuccess, Delay: 10 * time.Millisecond})
	health.Observe(Observation{NodeID: bad.ID, NodeSlot: 2, NodeVersion: 1, Scope: DomainTransport, Transport: "udp_dns/ipv4", Outcome: OutcomeFailure})
	engine := NewPolicyEngine(health, 2, "fallback")
	service := ServiceContext{ID: "dns-app", Mode: ModeAdaptive, Transport: N.NetworkUDP, HealthTransport: "udp_dns/ipv4"}
	plan, err := engine.Plan(testExecutionSnapshot(bad, good), service, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Candidates) == 0 || plan.Candidates[0].ID != good.ID {
		t.Fatalf("broken DNS path candidate was not filtered: %+v", plan.Candidates)
	}
	if reason := engine.ExclusionReason(bad, service); reason == "" {
		t.Fatal("expected exclusion reason for broken DNS path")
	}
}

func TestPolicyClearDropsStickyState(t *testing.T) {
	health := NewHealthStore(time.Hour, 8)
	incumbent := Candidate{ID: NodeID{221}, Handle: NodeHandle{NodeID: NodeID{221}, Slot: 1, Version: 1}, PrimaryTag: "a"}
	challenger := Candidate{ID: NodeID{222}, Handle: NodeHandle{NodeID: NodeID{222}, Slot: 2, Version: 1}, PrimaryTag: "b"}
	health.Observe(Observation{NodeID: incumbent.ID, NodeSlot: 1, NodeVersion: 1, Scope: DomainEndpoint, Outcome: OutcomeSuccess, Delay: 100 * time.Millisecond})
	health.Observe(Observation{NodeID: challenger.ID, NodeSlot: 2, NodeVersion: 1, Scope: DomainEndpoint, Outcome: OutcomeSuccess, Delay: 40 * time.Millisecond})
	engine := NewPolicyEngine(health, 2, "fallback").BindSwitchStability(0.15, time.Minute)
	service := ServiceContext{ID: "svc", AffinityID: "aff", Mode: ModeAdaptive, Transport: N.NetworkTCP}
	engine.RememberSelection(service.AffinityID, incumbent.Handle, time.Now())
	plan, err := engine.Plan(testExecutionSnapshot(challenger, incumbent), service, nil, nil)
	if err != nil || plan.Candidates[0].ID != incumbent.ID {
		t.Fatalf("cooldown should keep incumbent before clear: %+v err=%v", plan, err)
	}
	engine.Clear()
	plan, err = engine.Plan(testExecutionSnapshot(challenger, incumbent), service, nil, nil)
	if err != nil || plan.Candidates[0].ID != challenger.ID {
		t.Fatalf("clear should drop sticky preference: %+v err=%v", plan, err)
	}
}

func TestExclusionExplanationDoesNotAdvanceBreaker(t *testing.T) {
	store, clock := newBreakerTestStore()
	handle := NodeHandle{NodeID: NodeID{231}, Slot: 1, Version: 1}
	for range 3 {
		store.Observe(Observation{NodeID: handle.NodeID, NodeSlot: handle.Slot, NodeVersion: handle.Version, Scope: DomainEndpoint, Outcome: OutcomeFailure, At: clock.Now()})
	}
	service := ServiceContext{ID: "status", Transport: N.NetworkTCP}
	before := store.EndpointHandle(handle)
	if before.Breaker != BreakerOpen {
		t.Fatalf("breaker did not open: %+v", before)
	}
	if reason := store.ExplainExclusion(handle, service, clock.Now()); reason == "" {
		t.Fatal("open breaker had no exclusion explanation")
	}
	after := store.EndpointHandle(handle)
	if after.Breaker != before.Breaker || after.HalfOpen != before.HalfOpen || after.CooldownUntil != before.CooldownUntil {
		t.Fatalf("status explanation mutated breaker: before=%+v after=%+v", before, after)
	}
	clock.Advance(before.Backoff)
	if reason := store.ExplainExclusion(handle, service, clock.Now()); reason != "" {
		t.Fatalf("expired breaker remained unavailable in read-only view: %q", reason)
	}
	if current := store.EndpointHandle(handle); current.Breaker != BreakerOpen {
		t.Fatalf("read-only expiry check advanced stored breaker: %+v", current)
	}
}
