package group

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
)

const smartProbeRegistryLimit = 8192

var errSharedSmartProbeFailed = errors.New("shared smart probe failed")
var errSharedSmartProbeDeferred = errors.New("shared smart probe deferred")

type smartProbeResult struct {
	delay       uint16
	success     bool
	completedAt time.Time
	nextProbeAt time.Time
	successes   uint8
	failures    uint8
	deferred    bool
}

type smartProbeEntry struct {
	result   smartProbeResult
	inflight bool
	done     chan struct{}
}

type smartProbeRegistry struct {
	ctx             context.Context
	cancel          context.CancelFunc
	access          sync.Mutex
	entries         map[string]*smartProbeEntry
	probe           func(context.Context, string, adapter.Outbound) (uint16, error)
	slots           chan struct{}
	groups          atomic.Uint32
	completedProbes atomic.Uint64
}

func (r *smartProbeRegistry) startupDelay() time.Duration {
	if r == nil {
		return 0
	}
	order := r.groups.Add(1) - 1
	return time.Duration(min(order, uint32(4))) * 15 * time.Second
}

type smartProbeRegistryReference struct {
	registry *smartProbeRegistry
	refs     int
}

var smartProbeRegistries struct {
	sync.Mutex
	byProcess map[<-chan struct{}]*smartProbeRegistryReference
}

func acquireSmartProbeRegistry(ctx context.Context) (*smartProbeRegistry, func()) {
	processKey := ctx.Done()
	if processKey == nil {
		registry := newSmartProbeRegistry(ctx)
		return registry, registry.close
	}
	smartProbeRegistries.Lock()
	if smartProbeRegistries.byProcess == nil {
		smartProbeRegistries.byProcess = make(map[<-chan struct{}]*smartProbeRegistryReference)
	}
	reference := smartProbeRegistries.byProcess[processKey]
	if reference == nil {
		reference = &smartProbeRegistryReference{registry: newSmartProbeRegistry(ctx)}
		smartProbeRegistries.byProcess[processKey] = reference
	}
	reference.refs++
	registry := reference.registry
	smartProbeRegistries.Unlock()
	var once sync.Once
	return registry, func() {
		once.Do(func() {
			smartProbeRegistries.Lock()
			current := smartProbeRegistries.byProcess[processKey]
			if current == reference {
				current.refs--
				if current.refs == 0 {
					delete(smartProbeRegistries.byProcess, processKey)
					current.registry.close()
				}
			}
			smartProbeRegistries.Unlock()
		})
	}
}

func newSmartProbeRegistry(parent context.Context) *smartProbeRegistry {
	ctx, cancel := context.WithCancel(parent)
	return &smartProbeRegistry{
		ctx:     ctx,
		cancel:  cancel,
		entries: make(map[string]*smartProbeEntry),
		slots:   make(chan struct{}, 4),
		probe: func(ctx context.Context, link string, outbound adapter.Outbound) (uint16, error) {
			return urltest.URLTest(ctx, link, outbound)
		},
	}
}

func smartProbeKey(identity, probeURL string, timeout time.Duration) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte(identity))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(probeURL))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(timeout.String()))
	return hex.EncodeToString(digest.Sum(nil))
}

// failed reports a recent shared probe failure for a candidate. Probe
// outcomes are process-wide, so every Smart group avoids the same failed node
// until the shared TTL expires instead of rediscovering the failure itself.
func (r *smartProbeRegistry) failed(key string, ttl time.Duration) bool {
	if r == nil || key == "" {
		return false
	}
	if ttl <= 0 {
		ttl = time.Minute
	}
	r.access.Lock()
	defer r.access.Unlock()
	entry := r.entries[key]
	return entry != nil && !entry.inflight && !entry.result.success && !entry.result.nextProbeAt.IsZero() && time.Now().Before(entry.result.nextProbeAt)
}

func (r *smartProbeRegistry) dead(key string) bool {
	if r == nil || key == "" {
		return false
	}
	r.access.Lock()
	defer r.access.Unlock()
	entry := r.entries[key]
	return entry != nil && !entry.inflight && !entry.result.success && entry.result.failures >= 3
}

func smartProbeCadence(success bool, successes, failures uint8) time.Duration {
	if success {
		switch successes {
		case 0, 1:
			return 5 * time.Minute
		case 2:
			return 15 * time.Minute
		default:
			return 30 * time.Minute
		}
	}
	switch failures {
	case 0, 1:
		return 30 * time.Second
	case 2:
		return time.Minute
	default:
		return 5 * time.Minute
	}
}

func (r *smartProbeRegistry) run(ctx context.Context, key, probeURL string, timeout, ttl time.Duration, candidate adapter.Outbound) (uint16, error) {
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	if r.ctx.Err() != nil {
		return 0, r.ctx.Err()
	}
	if ttl <= 0 {
		ttl = time.Minute
	}
	now := time.Now()
	r.access.Lock()
	entry := r.entries[key]
	if entry != nil && !entry.inflight && now.Before(entry.result.nextProbeAt) {
		result := entry.result
		r.access.Unlock()
		if result.success {
			return result.delay, nil
		}
		if result.deferred {
			return 0, errSharedSmartProbeDeferred
		}
		return 0, errSharedSmartProbeFailed
	}
	if entry != nil && entry.inflight {
		done := entry.done
		r.access.Unlock()
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-r.ctx.Done():
			return 0, r.ctx.Err()
		case <-done:
		}
		r.access.Lock()
		result := entry.result
		r.access.Unlock()
		if result.success {
			return result.delay, nil
		}
		if result.deferred {
			return 0, errSharedSmartProbeDeferred
		}
		return 0, errSharedSmartProbeFailed
	}
	if len(r.entries) >= smartProbeRegistryLimit {
		r.pruneLocked(now)
		if len(r.entries) >= smartProbeRegistryLimit {
			r.access.Unlock()
			// Overflow path must honor the caller's ctx so shutdown cancels promptly.
			probeCtx, cancel := context.WithTimeout(ctx, timeout)
			if probeCtx.Err() != nil {
				cancel()
				return 0, probeCtx.Err()
			}
			delay, err := r.probe(probeCtx, probeURL, candidate)
			cancel()
			if err != nil {
				return 0, errSharedSmartProbeFailed
			}
			return delay, nil
		}
	}
	entry = &smartProbeEntry{inflight: true, done: make(chan struct{})}
	r.entries[key] = entry
	r.access.Unlock()

	select {
	case r.slots <- struct{}{}:
	case <-ctx.Done():
		r.access.Lock()
		entry.result = smartProbeResult{completedAt: time.Now(), nextProbeAt: time.Now(), deferred: true}
		entry.inflight = false
		close(entry.done)
		entry.done = nil
		r.access.Unlock()
		return 0, errSharedSmartProbeDeferred
	case <-r.ctx.Done():
		r.access.Lock()
		entry.result = smartProbeResult{completedAt: time.Now(), nextProbeAt: time.Now(), deferred: true}
		entry.inflight = false
		close(entry.done)
		entry.done = nil
		r.access.Unlock()
		return 0, errSharedSmartProbeDeferred
	}

	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	delay, err := r.probe(probeCtx, probeURL, candidate)
	cancel()
	// Release the admission slot before any optional GC so other groups
	// (and shutdown waiters) are never blocked behind a STW collection.
	<-r.slots
	// Probe transports are short-lived; throttle GC so HA restarts are not
	// serialized behind full heap scans after every single URL test.
	if n := r.completedProbes.Add(1); n%32 == 0 && r.ctx.Err() == nil && ctx.Err() == nil {
		runtime.GC()
	}
	completedAt := time.Now()
	r.access.Lock()
	previous := entry.result
	var successes, failures uint8
	if err == nil {
		successes = min(previous.successes+1, uint8(3))
	} else {
		failures = min(previous.failures+1, uint8(3))
	}
	result := smartProbeResult{
		delay: delay, success: err == nil, completedAt: completedAt,
		nextProbeAt: completedAt.Add(smartProbeCadence(err == nil, successes, failures)),
		successes:   successes, failures: failures,
	}
	entry.result = result
	entry.inflight = false
	close(entry.done)
	entry.done = nil
	r.access.Unlock()
	if err != nil {
		return 0, errSharedSmartProbeFailed
	}
	return delay, nil
}

func (r *smartProbeRegistry) pruneLocked(now time.Time) {
	for key, entry := range r.entries {
		if !entry.inflight && now.Sub(entry.result.completedAt) > time.Hour {
			delete(r.entries, key)
		}
	}
	for len(r.entries) >= smartProbeRegistryLimit {
		var oldestKey string
		var oldest time.Time
		for key, entry := range r.entries {
			if entry.inflight {
				continue
			}
			if oldestKey == "" || entry.result.completedAt.Before(oldest) {
				oldestKey = key
				oldest = entry.result.completedAt
			}
		}
		if oldestKey == "" {
			break
		}
		delete(r.entries, oldestKey)
	}
}

func (r *smartProbeRegistry) close() {
	r.cancel()
	r.access.Lock()
	clear(r.entries)
	r.entries = make(map[string]*smartProbeEntry)
	r.access.Unlock()
}
