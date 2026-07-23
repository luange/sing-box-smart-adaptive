package adaptive

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestBuiltinYouTubeTLSTargetProviderIsStaticRedactedAndRefreshable(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := &fakeClock{now: now}
	provider, err := NewBuiltinYouTubeTLSTargetProvider(clock)
	if err != nil {
		t.Fatal(err)
	}
	first, err := provider.Snapshot(context.Background(), youtubeProbeServiceID)
	if err != nil {
		t.Fatal(err)
	}
	targets, err := first.executionTargets(now)
	if err != nil || len(targets) != 1 {
		t.Fatalf("builtin target missing: targets=%d err=%v", len(targets), err)
	}
	if targets[0].Capability != ProbeCapabilityTLS || targets[0].executionURL() != "https://www.youtube.com/" {
		t.Fatalf("unexpected builtin target: %+v", targets[0].Descriptor())
	}
	if formatted := fmt.Sprintf("%+v %#v", first, targets[0]); strings.Contains(formatted, "youtube.com") {
		t.Fatalf("builtin execution host leaked through formatting: %s", formatted)
	}
	if err = provider.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	second, err := provider.Snapshot(context.Background(), youtubeProbeServiceID)
	if err != nil || second.Generation != first.Generation {
		t.Fatalf("fresh builtin target was needlessly rotated: generation=%d err=%v", second.Generation, err)
	}
	if _, err = provider.Snapshot(context.Background(), "chatgpt"); !errorsIs(err, ErrProbeRunUnknown) {
		t.Fatalf("builtin provider crossed service boundary: %v", err)
	}
}

func TestBuiltinAIServiceTargetsUseIndependentSafeProbeSemantics(t *testing.T) {
	now := time.Date(2026, time.July, 23, 0, 0, 0, 0, time.UTC)
	provider, err := NewBuiltinAIServiceTLSTargetProvider(&fakeClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string]struct {
		url        string
		capability ProbeCapability
	}{
		"youtube":     {"https://www.youtube.com/", ProbeCapabilityTLS},
		"gemini":      {"https://www.google.com/", ProbeCapabilityTLS},
		"openai_api":  {"https://api.openai.com/v1/models", ProbeCapabilityAuthHTTP},
		"chatgpt_web": {"https://chatgpt.com/", ProbeCapabilityWebWAF},
		"claude":      {"https://api.anthropic.com/v1/models", ProbeCapabilityAuthHTTP},
	}
	for serviceID, wanted := range expected {
		snapshot, snapshotErr := provider.Snapshot(context.Background(), serviceID)
		if snapshotErr != nil {
			t.Fatalf("snapshot %s: %v", serviceID, snapshotErr)
		}
		targets, targetsErr := snapshot.executionTargets(now)
		if targetsErr != nil {
			t.Fatalf("targets %s: %v", serviceID, targetsErr)
		}
		if len(targets) != 1 || targets[0].executionURL() != wanted.url || targets[0].Capability != wanted.capability {
			t.Fatalf("unexpected %s target: %+v", serviceID, targets)
		}
		formatted := fmt.Sprintf("%+v %#v", snapshot, targets[0])
		if strings.Contains(formatted, "api.openai.com") || strings.Contains(formatted, "api.anthropic.com") || strings.Contains(formatted, "chatgpt.com") || strings.Contains(formatted, "/v1/models") {
			t.Fatalf("execution endpoint leaked through formatting for %s: %s", serviceID, formatted)
		}
	}
}
