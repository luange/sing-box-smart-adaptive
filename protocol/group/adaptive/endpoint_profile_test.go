package adaptive

import (
	"testing"
	"time"
)

func TestEndpointProfileTracksAreIndependentAndDeduplicated(t *testing.T) {
	registry := NewEndpointProfileRegistry()
	endpoint := NodeID{1}
	if !registry.TryAcquire(endpoint, TrackTCP4) {
		t.Fatal("first TCP probe rejected")
	}
	if registry.TryAcquire(endpoint, TrackTCP4) {
		t.Fatal("duplicate TCP probe admitted")
	}
	if !registry.TryAcquire(endpoint, TrackDNSUDP4) {
		t.Fatal("independent DNS track was blocked")
	}
	registry.Release(endpoint, TrackTCP4)
	registry.Release(endpoint, TrackDNSUDP4)
}

func TestEndpointProfileCadence(t *testing.T) {
	registry := NewEndpointProfileRegistry()
	endpoint := NodeID{2}
	now := time.Unix(1_700_000_000, 0)
	registry.Record(endpoint, TrackTCP4, true, 10*time.Millisecond, now)
	profile, ok := registry.Snapshot(endpoint, TrackTCP4)
	if !ok || profile.NextProbeAt.Sub(now) != 5*time.Minute {
		t.Fatalf("first success cadence: %+v", profile)
	}
	registry.Record(endpoint, TrackTCP4, true, 9*time.Millisecond, now)
	profile, _ = registry.Snapshot(endpoint, TrackTCP4)
	if profile.NextProbeAt.Sub(now) != 15*time.Minute {
		t.Fatalf("second success cadence: %+v", profile)
	}
	registry.Record(endpoint, TrackTCP4, false, 0, now)
	profile, _ = registry.Snapshot(endpoint, TrackTCP4)
	if profile.NextProbeAt.Sub(now) != 30*time.Second || profile.Successes != 0 {
		t.Fatalf("first failure cadence: %+v", profile)
	}
}
