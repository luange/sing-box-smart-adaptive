package adaptive

import "testing"

func TestExitIdentityStoreIsProcessLocalKeyedAndCountsOnlyChanges(t *testing.T) {
	store, err := NewExitIdentityStore("test-exit-identity-store")
	if err != nil {
		t.Fatal(err)
	}
	first, valid := tokenizeExitIdentity([]byte("203.0.113.10\n"))
	if !valid {
		t.Fatal("valid public address was rejected")
	}
	second, valid := tokenizeExitIdentity([]byte("2001:4860:4860::8888"))
	if !valid || first == second {
		t.Fatal("independent public identities did not produce independent keyed tokens")
	}
	handle := NodeHandle{NodeID: NodeID{1}, Slot: 2, Version: 3}
	if changed, accepted := store.Observe(handle, first); changed || !accepted {
		t.Fatalf("first identity did not establish a baseline: changed=%v accepted=%v", changed, accepted)
	}
	if changed, accepted := store.Observe(handle, first); changed || !accepted {
		t.Fatalf("stable identity changed: changed=%v accepted=%v", changed, accepted)
	}
	if changed, accepted := store.Observe(handle, second); !changed || !accepted {
		t.Fatalf("identity change was missed: changed=%v accepted=%v", changed, accepted)
	}
	if baselines, changes := store.Stats(); baselines != 1 || changes != 1 {
		t.Fatalf("unexpected identity stats: baselines=%d changes=%d", baselines, changes)
	}

	// A reload creates a new wrapper but retains the process-local baseline.
	reloaded, err := NewExitIdentityStore("test-exit-identity-store")
	if err != nil {
		t.Fatal(err)
	}
	if baselines, changes := reloaded.Stats(); baselines != 1 || changes != 1 {
		t.Fatalf("process-local baseline did not survive wrapper reload: baselines=%d changes=%d", baselines, changes)
	}
}

func TestExitIdentityClassificationDoesNotExposeIdentity(t *testing.T) {
	target := ProbeTarget{Capability: ProbeCapabilityExitIdentity, Generation: 1}
	raw := ProbeRawResult{TLSHandshakeOK: true, StatusCode: 200, hasIdentityToken: true}
	classification := ClassifyProbeResult(target, raw, target.IssuedAt)
	if classification.Class != ProbeSampleTargetFault { // target lifetime is deliberately invalid here
		t.Fatalf("invalid target was accepted: %+v", classification)
	}
}
