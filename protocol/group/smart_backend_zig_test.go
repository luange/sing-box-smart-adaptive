//go:build smart_zig && cgo

package group

import (
	"testing"
	"time"
)

func TestZigSmartBackendHonorsSiteAffinityLease(t *testing.T) {
	backend := newSmartPolicyBackend(smartPolicyBackendConfig{
		Exploration: 0, SwitchMargin: 0, SwitchConfirm: 1,
		SwitchConfirmWindow: 0, SwitchCooldown: 0,
	})
	if backend == nil {
		t.Fatal("zig backend was not constructed")
	}
	defer backend.Close()
	now := time.Now()
	candidates := []smartPolicyCandidate{
		{ID: 1, Reliability: .99, ConnectMS: 5, FirstByteMS: 5, Samples: 10, Weight: 1, State: smartPolicyState("healthy"), Eligible: true},
		{ID: 2, Reliability: .50, ConnectMS: 500, FirstByteMS: 500, Samples: 10, Weight: 1, State: smartPolicyState("healthy"), Eligible: true},
	}
	key := "network\x00site\x00tcp"
	if got := backend.Choose(key, candidates, smartProfileInteractive, now); got.SelectedID != 1 {
		t.Fatalf("initial selection = %d, want 1", got.SelectedID)
	}
	backend.Stick(key, 2, now, now.Add(time.Minute))
	if got := backend.Choose(key, candidates, smartProfileInteractive, now.Add(10*time.Second)); got.SelectedID != 2 {
		t.Fatalf("sticky selection = %d, want 2", got.SelectedID)
	}
	if got := backend.Selected(key); got != 2 {
		t.Fatalf("backend selected id = %d, want 2", got)
	}
}
