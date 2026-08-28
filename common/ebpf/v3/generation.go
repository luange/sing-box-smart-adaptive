package v3

import "sync/atomic"

// BankPublisher implements double-buffer policy publish (design §7.1).
// Never mutates the active bank in place.
type BankPublisher struct {
	active     atomic.Uint32 // 0 or 1
	generation atomic.Uint32
	compiling  atomic.Uint32 // 1 while inactive bank is being filled
}

// NewBankPublisher starts at bank 0, generation 1.
func NewBankPublisher() *BankPublisher {
	p := &BankPublisher{}
	p.generation.Store(1)
	return p
}

// ActiveBank returns the currently live bank index.
func (p *BankPublisher) ActiveBank() uint32 {
	if p == nil {
		return 0
	}
	return p.active.Load()
}

// Generation returns the live policy generation.
func (p *BankPublisher) Generation() uint32 {
	if p == nil {
		return 0
	}
	return p.generation.Load()
}

// InactiveBank is the bank currently safe to fill.
func (p *BankPublisher) InactiveBank() uint32 {
	return 1 - p.ActiveBank()
}

// BeginCompile marks inactive bank fill. Concurrent BeginCompile fails.
func (p *BankPublisher) BeginCompile() (inactive uint32, ok bool) {
	if p == nil {
		return 0, false
	}
	if !p.compiling.CompareAndSwap(0, 1) {
		return 0, false
	}
	return p.InactiveBank(), true
}

// AbortCompile releases the compile lock without flipping banks.
func (p *BankPublisher) AbortCompile() {
	if p == nil {
		return
	}
	p.compiling.Store(0)
}

// Commit flips active_bank and bumps generation atomically from the caller's
// perspective: generation is incremented first is wrong — we set generation then
// bank so old flow entries (keyed by old gen) miss immediately after bank flip.
// Order: store new generation, then active bank, then clear compiling.
func (p *BankPublisher) Commit() (generation uint32, active uint32) {
	if p == nil {
		return 0, 0
	}
	newGen := nextGeneration(p.generation.Load())
	newActive := p.InactiveBank()
	p.generation.Store(newGen)
	p.active.Store(newActive)
	p.compiling.Store(0)
	return newGen, newActive
}

// AdvanceGeneration invalidates entries from the current generation without
// changing the active policy bank. It is used by route/interface reloads that
// must retire learned flows before the next static-policy commit.
func (p *BankPublisher) AdvanceGeneration() uint32 {
	if p == nil {
		return 0
	}
	for {
		current := p.generation.Load()
		next := nextGeneration(current)
		if p.generation.CompareAndSwap(current, next) {
			return next
		}
	}
}

func nextGeneration(current uint32) uint32 {
	next := current + 1
	if next == 0 {
		next = 1
	}
	return next
}

// Snapshot is a stable view for writing Control.
func (p *BankPublisher) Snapshot() (bank uint32, generation uint32) {
	if p == nil {
		return 0, 0
	}
	// Read generation then bank; worst case a concurrent Commit makes us write
	// an older bank with newer gen once — next packet still fails gen check on flows.
	g := p.generation.Load()
	b := p.active.Load()
	return b, g
}

// SyncGeneration raises the publisher generation to a live kernel generation
// observed by a caller. It is intentionally monotonic: a stale observation
// must never make a subsequent userspace commit reuse an older generation.
func (p *BankPublisher) SyncGeneration(generation uint32) {
	if p == nil || generation == 0 {
		return
	}
	for {
		current := p.generation.Load()
		if !generationNewer(generation, current) {
			return
		}
		if p.generation.CompareAndSwap(current, generation) {
			return
		}
	}
}

// generationNewer uses serial-number arithmetic so the uint32 generation can
// wrap from max uint32 to 1 without treating the wrapped value as stale. A
// difference of exactly 2^31 is undefined by design and is treated as not
// newer; generations are expected to advance by a tiny fraction of that.
func generationNewer(candidate, current uint32) bool {
	return candidate != current && int32(candidate-current) > 0
}
