//go:build smart_zig && cgo

package conformance

import "testing"

func TestZigMatchesReferenceTransitions(t *testing.T) {
	config := Config{SwitchMargin: .05, SwitchConfirmSamples: 2, SwitchConfirmMS: 1000, SwitchCooldownMS: 2000}
	engine := newZigEngine(config)
	if engine == nil || engine.ptr == nil {
		t.Fatal("smart_engine_create returned nil")
	}
	defer engine.close()
	candidates := []Candidate{{ID: 1, Reliability: .9, ConnectMS: 20, FirstByteMS: 20, JitterMS: 1, Samples: 4, Weight: 1, State: 1, Eligible: 1}, {ID: 2, Reliability: .99, ConnectMS: 5, FirstByteMS: 5, JitterMS: 1, Samples: 4, Weight: 1, State: 1, Eligible: 1}}
	var reference state
	for _, now := range []uint64{0, 1000, 2000, 2500} {
		wantCandidates := candidates
		if now == 0 {
			wantCandidates = candidates[:1]
		}
		want := choose(&reference, config, wantCandidates, now)
		got := engine.choose(wantCandidates, now)
		if got.SelectedID != want.SelectedID || got.Switched != want.Switched || got.Reason != want.Reason {
			t.Fatalf("at %d: got id=%d switched=%d reason=%d, want id=%d switched=%d reason=%d", now, got.SelectedID, got.Switched, got.Reason, want.SelectedID, want.Switched, want.Reason)
		}
	}
}
