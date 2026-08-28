//go:build smart_zig && cgo

package conformance

/*
#cgo CFLAGS: -I${SRCDIR}/../include
#cgo LDFLAGS: -L${SRCDIR}/../zig-out/lib -lsmart_engine -lm
#include "smart_engine.h"
*/
import "C"

import "testing"

func toC(value Candidate) C.smart_candidate {
	return C.smart_candidate{
		id: C.uint64_t(value.ID), reliability: C.double(value.Reliability), connect_ms: C.double(value.ConnectMS),
		first_byte_ms: C.double(value.FirstByteMS), jitter_ms: C.double(value.JitterMS), throughput_bps: C.double(value.ThroughputBPS),
		samples: C.double(value.Samples), weight: C.double(value.Weight), state: C.uint8_t(value.State), eligible: C.uint8_t(value.Eligible),
	}
}

func TestZigMatchesReferenceTransitions(t *testing.T) {
	config := Config{SwitchMargin: .05, SwitchConfirmSamples: 2, SwitchConfirmMS: 1000, SwitchCooldownMS: 2000}
	cfg := C.smart_engine_config{exploration: C.double(config.Exploration), switch_margin: C.double(config.SwitchMargin), switch_confirm_samples: C.uint32_t(config.SwitchConfirmSamples), switch_confirm_ms: C.uint64_t(config.SwitchConfirmMS), switch_cooldown_ms: C.uint64_t(config.SwitchCooldownMS)}
	engine := C.smart_engine_create(cfg)
	if engine == nil {
		t.Fatal("smart_engine_create returned nil")
	}
	defer C.smart_engine_destroy(engine)
	candidates := []Candidate{{ID: 1, Reliability: .9, ConnectMS: 20, FirstByteMS: 20, JitterMS: 1, Samples: 4, Weight: 1, State: 1, Eligible: 1}, {ID: 2, Reliability: .99, ConnectMS: 5, FirstByteMS: 5, JitterMS: 1, Samples: 4, Weight: 1, State: 1, Eligible: 1}}
	var reference state
	for _, now := range []uint64{0, 1000, 2000, 2500} {
		var cCandidates []C.smart_candidate
		if now == 0 {
			cCandidates = []C.smart_candidate{toC(candidates[0])}
		} else {
			cCandidates = []C.smart_candidate{toC(candidates[0]), toC(candidates[1])}
		}
		wantCandidates := candidates
		if now == 0 {
			wantCandidates = candidates[:1]
		}
		want := choose(&reference, config, wantCandidates, now)
		got := C.smart_engine_choose(engine, &cCandidates[0], C.uintptr_t(len(cCandidates)), C.uint64_t(now))
		if uint64(got.selected_id) != want.SelectedID || uint8(got.switched) != want.Switched || uint8(got.reason) != want.Reason {
			t.Fatalf("at %d: got id=%d switched=%d reason=%d, want id=%d switched=%d reason=%d", now, got.selected_id, got.switched, got.reason, want.SelectedID, want.Switched, want.Reason)
		}
	}
}
