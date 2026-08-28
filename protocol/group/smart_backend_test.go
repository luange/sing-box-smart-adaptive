package group

import "testing"

func TestBetterSmartPolicyCandidatePrefersUsableDuplicate(t *testing.T) {
	open := smartPolicyCandidate{State: smartPolicyState("open"), Reliability: 1, Samples: 20, ConnectMS: 1}
	healthy := smartPolicyCandidate{State: smartPolicyState("healthy"), Reliability: .5, Samples: 1, ConnectMS: 200}
	if !betterSmartPolicyCandidate(healthy, open) {
		t.Fatal("healthy duplicate must outrank an open stale provider line")
	}
	if betterSmartPolicyCandidate(open, healthy) {
		t.Fatal("open stale provider line must not replace a usable duplicate")
	}
}

func TestBetterSmartPolicyCandidateKeepsStrongestEvidence(t *testing.T) {
	weak := smartPolicyCandidate{State: smartPolicyState("healthy"), Reliability: .99, Samples: 10, ConnectMS: 30, FirstByteMS: 40, Throughput: 5}
	strong := smartPolicyCandidate{State: smartPolicyState("healthy"), Reliability: .99, Samples: 10, ConnectMS: 10, FirstByteMS: 20, Throughput: 10}
	if !betterSmartPolicyCandidate(strong, weak) {
		t.Fatal("lower latency duplicate with equal reliability/evidence should win")
	}
}
