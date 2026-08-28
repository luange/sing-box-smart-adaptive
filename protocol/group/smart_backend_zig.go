//go:build smart_zig && cgo

package group

/*
#cgo CFLAGS: -I${SRCDIR}/../../smart-engine/include
#cgo LDFLAGS: -L${SRCDIR}/../../smart-engine/zig-out/lib -lsmart_engine -lm
#include "smart_engine.h"
*/
import "C"

import (
	"sync"
	"time"
)

type smartPolicyBackendConfig struct {
	Exploration         float64
	SwitchMargin        float64
	SwitchConfirm       int
	SwitchConfirmWindow int64
	SwitchCooldown      int64
}

type zigSmartPolicyBackend struct {
	access  sync.Mutex
	config  C.smart_engine_config
	engines map[string]*zigSmartPolicyEngine
}

type zigSmartPolicyEngine struct {
	engine  *C.smart_engine
	lastUse time.Time
}

func newSmartPolicyBackend(config smartPolicyBackendConfig) smartPolicyBackend {
	cfg := C.smart_engine_config{
		exploration:            C.double(config.Exploration),
		switch_margin:          C.double(config.SwitchMargin),
		switch_confirm_samples: C.uint32_t(config.SwitchConfirm),
		switch_confirm_ms:      C.uint64_t(maxInt64(config.SwitchConfirmWindow)),
		switch_cooldown_ms:     C.uint64_t(maxInt64(config.SwitchCooldown)),
	}
	if C.smart_engine_abi_version() != 1 {
		return nil
	}
	return &zigSmartPolicyBackend{config: cfg, engines: make(map[string]*zigSmartPolicyEngine)}
}

func maxInt64(value int64) int64 {
	if value < 0 {
		return 0
	}
	return value
}

func smartMillis(now time.Time) uint64 {
	if now.IsZero() {
		now = time.Now()
	}
	return uint64(maxInt64(now.UnixMilli()))
}

func (b *zigSmartPolicyBackend) Choose(key string, candidates []smartPolicyCandidate, profile smartTrafficProfile, now time.Time) smartPolicyDecision {
	if b == nil || key == "" || len(candidates) == 0 || len(candidates) > 8192 {
		return smartPolicyDecision{Score: 100, Reason: 3}
	}
	engine := b.engineFor(key, now)
	if engine == nil {
		return smartPolicyDecision{Score: 100, Reason: 3}
	}
	converted := make([]C.smart_candidate, len(candidates))
	for i, candidate := range candidates {
		converted[i] = C.smart_candidate{
			id: C.uint64_t(candidate.ID), reliability: C.double(candidate.Reliability),
			connect_ms: C.double(candidate.ConnectMS), first_byte_ms: C.double(candidate.FirstByteMS),
			jitter_ms: C.double(candidate.JitterMS), throughput_bps: C.double(candidate.Throughput),
			samples: C.double(candidate.Samples), weight: C.double(candidate.Weight),
			state: C.uint8_t(candidate.State), eligible: C.uint8_t(boolByte(candidate.Eligible)),
		}
	}
	profileID := C.uint8_t(0)
	if profile == smartProfileBulk {
		profileID = 1
	} else if profile == smartProfileUDP {
		profileID = 2
	}
	decision := C.smart_engine_choose_profile(engine, &converted[0], C.uintptr_t(len(converted)), C.uint64_t(smartMillis(now)), profileID)
	return smartPolicyDecision{SelectedID: uint64(decision.selected_id), Score: float64(decision.score), Switched: decision.switched != 0, Reason: uint8(decision.reason)}
}

func (b *zigSmartPolicyBackend) engineFor(key string, now time.Time) *C.smart_engine {
	b.access.Lock()
	defer b.access.Unlock()
	if current := b.engines[key]; current != nil {
		current.lastUse = now
		return current.engine
	}
	// Keep context sharding bounded. Each policy engine owns a fixed 4096-slot
	// observation table, so unbounded site/network churn would defeat the
	// memory bound even though every individual engine is bounded.
	const maxContexts = 64
	if len(b.engines) >= maxContexts {
		var oldestKey string
		var oldest time.Time
		for candidateKey, candidate := range b.engines {
			if oldestKey == "" || candidate.lastUse.Before(oldest) {
				oldestKey, oldest = candidateKey, candidate.lastUse
			}
		}
		if evicted := b.engines[oldestKey]; evicted != nil {
			C.smart_engine_destroy(evicted.engine)
			delete(b.engines, oldestKey)
		}
	}
	engine := C.smart_engine_create(b.config)
	if engine == nil {
		return nil
	}
	b.engines[key] = &zigSmartPolicyEngine{engine: engine, lastUse: now}
	return engine
}

func boolByte(value bool) uint8 {
	if value {
		return 1
	}
	return 0
}

func (b *zigSmartPolicyBackend) Observe(key string, id uint64, success bool, elapsed time.Duration, now time.Time) {
	if b == nil || key == "" || id == 0 {
		return
	}
	engine := b.engineFor(key, now)
	if engine == nil {
		return
	}
	ms := float64(elapsed) / float64(time.Millisecond)
	if ms < 0 {
		ms = 0
	}
	C.smart_engine_observe(engine, C.uint64_t(id), C.uint8_t(boolByte(success)), C.double(ms), C.uint64_t(smartMillis(now)))
}

func (b *zigSmartPolicyBackend) Reset() {
	if b != nil {
		b.access.Lock()
		defer b.access.Unlock()
		for _, engine := range b.engines {
			C.smart_engine_reset(engine.engine)
		}
	}
}

func (b *zigSmartPolicyBackend) Close() {
	if b != nil {
		b.access.Lock()
		defer b.access.Unlock()
		for key, engine := range b.engines {
			C.smart_engine_destroy(engine.engine)
			delete(b.engines, key)
		}
	}
}
