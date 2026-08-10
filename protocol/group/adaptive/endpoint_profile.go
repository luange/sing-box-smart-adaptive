package adaptive

import "sync"

// EndpointProfileRegistry deduplicates in-flight probes across Smart and
// AdaptivePool consumers. Health evidence remains in each pool's HealthStore;
// this registry only owns endpoint-level probe admission and cadence state.
type EndpointProfileRegistry struct {
	mu     sync.Mutex
	active map[NodeID]struct{}
}

var globalEndpointProfiles = NewEndpointProfileRegistry()

func NewEndpointProfileRegistry() *EndpointProfileRegistry {
	return &EndpointProfileRegistry{active: make(map[NodeID]struct{})}
}

func (r *EndpointProfileRegistry) TryAcquire(endpointID NodeID) bool {
	if r == nil || endpointID == (NodeID{}) {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.active[endpointID]; ok {
		return false
	}
	r.active[endpointID] = struct{}{}
	return true
}

func (r *EndpointProfileRegistry) Release(endpointID NodeID) {
	if r == nil || endpointID == (NodeID{}) {
		return
	}
	r.mu.Lock()
	delete(r.active, endpointID)
	r.mu.Unlock()
}
