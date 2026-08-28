//go:build smart_zig && cgo

package adaptive

/*
#cgo CFLAGS: -I${SRCDIR}/../../../smart-engine/include
#cgo LDFLAGS: -L${SRCDIR}/../../../smart-engine/zig-out/lib -lsmart_engine -lm
#include "smart_engine.h"
*/
import "C"

import (
	"sync"
	"time"
)

const (
	adaptiveKernelShardCount       = 16
	adaptiveKernelMaxContexts      = 128
	adaptiveKernelContextsPerShard = adaptiveKernelMaxContexts / adaptiveKernelShardCount
)

type zigAdaptivePolicyKernel struct {
	configAccess sync.RWMutex
	config       C.adaptive_engine_config
	shards       [adaptiveKernelShardCount]adaptivePolicyShard
}

type adaptivePolicyShard struct {
	access     sync.Mutex
	engines    map[string]*adaptivePolicyEngine
	candidates []C.adaptive_candidate
}

type adaptivePolicyEngine struct {
	engine  *C.adaptive_engine
	lastUse time.Time
}

// Native policy timestamps are process-relative rather than wall-clock
// milliseconds. This keeps confirmation/cooldown behavior correct when NTP or
// an operator changes the system clock while the process is running.
var adaptiveKernelClockOrigin = time.Now()

func newAdaptivePolicyKernel() policyKernel {
	if C.adaptive_engine_abi_version() != 3 {
		return nil
	}
	kernel := &zigAdaptivePolicyKernel{config: C.adaptive_engine_config{
		switch_margin: C.double(defaultSwitchMargin), switch_cooldown_ms: C.uint64_t(defaultSwitchCooldown / time.Millisecond),
		switch_confirm_samples: C.uint32_t(defaultSwitchConfirmSamples), switch_confirm_ms: C.uint64_t(defaultSwitchConfirm / time.Millisecond),
	}}
	for index := range kernel.shards {
		kernel.shards[index].engines = make(map[string]*adaptivePolicyEngine)
	}
	return kernel
}

func (k *zigAdaptivePolicyKernel) Configure(margin float64, cooldown, confirm time.Duration, confirmSamples int, manualFailure string) {
	if k == nil {
		return
	}
	if margin < 0 {
		margin = defaultSwitchMargin
	}
	if margin > 0.95 {
		margin = 0.95
	}
	if cooldown < 0 {
		cooldown = 0
	}
	if confirm <= 0 {
		confirm = defaultSwitchConfirm
	}
	if confirmSamples <= 0 {
		confirmSamples = defaultSwitchConfirmSamples
	}
	config := C.adaptive_engine_config{
		switch_margin: C.double(margin), switch_cooldown_ms: C.uint64_t(cooldown / time.Millisecond),
		switch_confirm_samples: C.uint32_t(confirmSamples), switch_confirm_ms: C.uint64_t(confirm / time.Millisecond),
	}
	if manualFailure == "fail_closed" {
		config.manual_failure = 1
	}
	k.configAccess.Lock()
	k.config = config
	k.configAccess.Unlock()
	for index := range k.shards {
		shard := &k.shards[index]
		shard.access.Lock()
		for _, engine := range shard.engines {
			C.adaptive_engine_configure(engine.engine, config)
		}
		shard.access.Unlock()
	}
}

func (k *zigAdaptivePolicyKernel) configSnapshot() C.adaptive_engine_config {
	k.configAccess.RLock()
	config := k.config
	k.configAccess.RUnlock()
	return config
}

func (k *zigAdaptivePolicyKernel) Choose(key string, candidates []policyKernelCandidate, mode PolicyMode, now time.Time) policyKernelDecision {
	if k == nil || key == "" || len(candidates) == 0 || len(candidates) > 8192 {
		return policyKernelDecision{}
	}
	if now.IsZero() {
		now = time.Now()
	}
	shard := k.shardFor(key)
	shard.access.Lock()
	defer shard.access.Unlock()
	engine := k.engineLocked(shard, key, now)
	if engine == nil {
		return policyKernelDecision{}
	}
	if cap(shard.candidates) < len(candidates) {
		shard.candidates = make([]C.adaptive_candidate, len(candidates))
	} else {
		shard.candidates = shard.candidates[:len(candidates)]
	}
	for index, candidate := range candidates {
		shard.candidates[index] = C.adaptive_candidate{
			id: C.uint64_t(candidate.ID), sort_key_hi: C.uint64_t(candidate.SortKeyHi), sort_key_lo: C.uint64_t(candidate.SortKeyLo), health_priority: C.int32_t(candidate.HealthPriority),
			weighted_delay_ms: C.double(candidate.WeightedDelayMS), throughput_bps: C.double(candidate.ThroughputBPS), throughput_samples: C.double(candidate.ThroughputSamples),
			supported: C.uint8_t(boolByte(candidate.Supported)), eligible: C.uint8_t(boolByte(candidate.Eligible)), pinned: C.uint8_t(boolByte(candidate.Pinned)), leased: C.uint8_t(boolByte(candidate.Leased)),
		}
	}
	config := k.configSnapshot()
	config.mode = C.uint8_t(policyKernelMode(mode))
	C.adaptive_engine_configure(engine.engine, config)
	decision := C.adaptive_engine_choose(engine.engine, &shard.candidates[0], C.uintptr_t(len(shard.candidates)), C.uint64_t(kernelNowMS(now)))
	return policyKernelDecision{SelectedID: uint64(decision.selected_id), Switched: decision.switched != 0, Reason: uint8(decision.reason)}
}

func (k *zigAdaptivePolicyKernel) SetBulkSequence(key string, sequence uint64) {
	if k == nil || key == "" {
		return
	}
	shard := k.shardFor(key)
	shard.access.Lock()
	defer shard.access.Unlock()
	if engine := k.engineLocked(shard, key, time.Now()); engine != nil {
		C.adaptive_engine_set_bulk_sequence(engine.engine, C.uint64_t(sequence))
	}
}

func (k *zigAdaptivePolicyKernel) Remember(key string, id NodeID, now time.Time, cooldown time.Duration) {
	if k == nil || key == "" || id == (NodeID{}) {
		return
	}
	if now.IsZero() {
		now = time.Now()
	}
	shard := k.shardFor(key)
	shard.access.Lock()
	defer shard.access.Unlock()
	if engine := k.engineLocked(shard, key, now); engine != nil {
		C.adaptive_engine_remember(engine.engine, C.uint64_t(kernelCandidateID(id)), C.uint64_t(kernelNowMS(now)), C.uint64_t(maxDurationMS(cooldown)))
	}
}

func (k *zigAdaptivePolicyKernel) Forget(key string) {
	if k == nil || key == "" {
		return
	}
	shard := k.shardFor(key)
	shard.access.Lock()
	defer shard.access.Unlock()
	if engine := shard.engines[key]; engine != nil {
		C.adaptive_engine_forget(engine.engine)
	}
}

func (k *zigAdaptivePolicyKernel) shardFor(key string) *adaptivePolicyShard {
	return &k.shards[adaptivePolicyShardIndex(key)]
}

func adaptivePolicyShardIndex(key string) int {
	return int(kernelHash(key) & (adaptiveKernelShardCount - 1))
}

func kernelHash(value string) uint64 {
	var hash uint64 = 14695981039346656037
	for index := 0; index < len(value); index++ {
		hash ^= uint64(value[index])
		hash *= 1099511628211
	}
	return hash
}

func (k *zigAdaptivePolicyKernel) engineLocked(shard *adaptivePolicyShard, key string, now time.Time) *adaptivePolicyEngine {
	if engine := shard.engines[key]; engine != nil {
		engine.lastUse = now
		return engine
	}
	if len(shard.engines) >= adaptiveKernelContextsPerShard {
		var oldestKey string
		var oldest time.Time
		for candidateKey, candidate := range shard.engines {
			if oldestKey == "" || candidate.lastUse.Before(oldest) {
				oldestKey, oldest = candidateKey, candidate.lastUse
			}
		}
		if evicted := shard.engines[oldestKey]; evicted != nil {
			C.adaptive_engine_destroy(evicted.engine)
			delete(shard.engines, oldestKey)
		}
	}
	engine := C.adaptive_engine_create(k.configSnapshot())
	if engine == nil {
		return nil
	}
	state := &adaptivePolicyEngine{engine: engine, lastUse: now}
	shard.engines[key] = state
	return state
}

func (k *zigAdaptivePolicyKernel) Reset() {
	if k == nil {
		return
	}
	for index := range k.shards {
		shard := &k.shards[index]
		shard.access.Lock()
		for key, engine := range shard.engines {
			C.adaptive_engine_destroy(engine.engine)
			delete(shard.engines, key)
		}
		shard.candidates = nil
		shard.access.Unlock()
	}
}

func (k *zigAdaptivePolicyKernel) Close() { k.Reset() }

func kernelNowMS(now time.Time) int64 {
	if now.IsZero() {
		now = time.Now()
	}
	elapsed := now.Sub(adaptiveKernelClockOrigin)
	if elapsed <= 0 {
		return 0
	}
	return elapsed.Milliseconds()
}

func maxDurationMS(value time.Duration) int64 {
	if value <= 0 {
		return 0
	}
	return int64(value / time.Millisecond)
}

func boolByte(value bool) uint8 {
	if value {
		return 1
	}
	return 0
}
