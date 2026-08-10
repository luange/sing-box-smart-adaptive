package adaptive

import (
	"context"
	"sync"
	"time"
)

type EndpointProbeTrack string

const (
	TrackTCP4     EndpointProbeTrack = "tcp4"
	TrackTCP6     EndpointProbeTrack = "tcp6"
	TrackDNSUDP4  EndpointProbeTrack = "dns_udp4"
	TrackDNSUDP6  EndpointProbeTrack = "dns_udp6"
	TrackDataUDP4 EndpointProbeTrack = "data_udp4"
	TrackDataUDP6 EndpointProbeTrack = "data_udp6"
)

type endpointProbeKey struct {
	endpoint NodeID
	track    EndpointProbeTrack
}

type EndpointTrackProfile struct {
	Healthy     bool
	Delay       time.Duration
	UpdatedAt   time.Time
	Successes   uint8
	Failures    uint8
	NextProbeAt time.Time
}

// EndpointProfileRegistry deduplicates in-flight probes across Smart and
// AdaptivePool consumers. Health evidence remains in each pool's HealthStore;
// this registry only owns endpoint-level probe admission and cadence state.
type EndpointProfileRegistry struct {
	mu       sync.Mutex
	active   map[endpointProbeKey]chan struct{}
	profiles map[endpointProbeKey]EndpointTrackProfile
}

var globalEndpointProfiles = NewEndpointProfileRegistry()

func NewEndpointProfileRegistry() *EndpointProfileRegistry {
	return &EndpointProfileRegistry{active: make(map[endpointProbeKey]chan struct{}), profiles: make(map[endpointProbeKey]EndpointTrackProfile)}
}

func (r *EndpointProfileRegistry) TryAcquire(endpointID NodeID, track EndpointProbeTrack) bool {
	if r == nil || endpointID == (NodeID{}) {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	key := endpointProbeKey{endpoint: endpointID, track: track}
	if _, ok := r.active[key]; ok {
		return false
	}
	r.active[key] = make(chan struct{})
	return true
}

func (r *EndpointProfileRegistry) Acquire(ctx context.Context, endpointID NodeID, track EndpointProbeTrack) bool {
	if r == nil || endpointID == (NodeID{}) {
		return true
	}
	key := endpointProbeKey{endpoint: endpointID, track: track}
	for {
		r.mu.Lock()
		done := r.active[key]
		if done == nil {
			r.active[key] = make(chan struct{})
			r.mu.Unlock()
			return true
		}
		r.mu.Unlock()
		select {
		case <-ctx.Done():
			return false
		case <-done:
		}
	}
}

func (r *EndpointProfileRegistry) Release(endpointID NodeID, track EndpointProbeTrack) {
	if r == nil || endpointID == (NodeID{}) {
		return
	}
	key := endpointProbeKey{endpoint: endpointID, track: track}
	r.mu.Lock()
	if done := r.active[key]; done != nil {
		delete(r.active, key)
		close(done)
	}
	r.mu.Unlock()
}

func (r *EndpointProfileRegistry) Record(endpointID NodeID, track EndpointProbeTrack, success bool, delay time.Duration, now time.Time) {
	if r == nil || endpointID == (NodeID{}) {
		return
	}
	key := endpointProbeKey{endpoint: endpointID, track: track}
	r.mu.Lock()
	profile := r.profiles[key]
	profile.Healthy, profile.Delay, profile.UpdatedAt = success, delay, now
	if success {
		profile.Successes = min(profile.Successes+1, uint8(3))
		profile.Failures = 0
		profile.NextProbeAt = now.Add(smartProfileCadence(true, profile.Successes))
	} else {
		profile.Failures = min(profile.Failures+1, uint8(3))
		profile.Successes = 0
		profile.NextProbeAt = now.Add(smartProfileCadence(false, profile.Failures))
	}
	r.profiles[key] = profile
	r.mu.Unlock()
}

func smartProfileCadence(success bool, streak uint8) time.Duration {
	if success {
		switch streak {
		case 0, 1:
			return 5 * time.Minute
		case 2:
			return 15 * time.Minute
		default:
			return 30 * time.Minute
		}
	}
	switch streak {
	case 0, 1:
		return 30 * time.Second
	case 2:
		return time.Minute
	default:
		return 5 * time.Minute
	}
}

func (r *EndpointProfileRegistry) Snapshot(endpointID NodeID, track EndpointProbeTrack) (EndpointTrackProfile, bool) {
	if r == nil {
		return EndpointTrackProfile{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.profiles[endpointProbeKey{endpoint: endpointID, track: track}]
	return p, ok
}
