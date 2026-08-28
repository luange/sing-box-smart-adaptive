package v3

import "testing"

func TestBankPublisherDoubleBuffer(t *testing.T) {
	p := NewBankPublisher()
	if p.ActiveBank() != 0 || p.Generation() != 1 {
		t.Fatalf("start bank=%d gen=%d", p.ActiveBank(), p.Generation())
	}
	inactive, ok := p.BeginCompile()
	if !ok || inactive != 1 {
		t.Fatalf("inactive=%d ok=%v", inactive, ok)
	}
	if _, ok := p.BeginCompile(); ok {
		t.Fatal("concurrent compile must fail")
	}
	gen, active := p.Commit()
	if gen != 2 || active != 1 {
		t.Fatalf("after commit gen=%d active=%d", gen, active)
	}
	// Old generation entries must not match new snapshot.
	bank, g := p.Snapshot()
	if bank != 1 || g != 2 {
		t.Fatalf("snapshot bank=%d gen=%d", bank, g)
	}
}

func TestBankPublisherAbort(t *testing.T) {
	p := NewBankPublisher()
	_, ok := p.BeginCompile()
	if !ok {
		t.Fatal("begin")
	}
	p.AbortCompile()
	if p.ActiveBank() != 0 || p.Generation() != 1 {
		t.Fatal("abort must not flip")
	}
	if _, ok := p.BeginCompile(); !ok {
		t.Fatal("should allow compile after abort")
	}
}

func TestBankPublisherSyncGenerationIsMonotonic(t *testing.T) {
	p := NewBankPublisher()
	p.SyncGeneration(10)
	if got := p.Generation(); got != 10 {
		t.Fatalf("generation=%d, want 10", got)
	}
	p.SyncGeneration(3)
	if got := p.Generation(); got != 10 {
		t.Fatalf("stale sync regressed generation to %d", got)
	}
	if _, ok := p.BeginCompile(); !ok {
		t.Fatal("begin after sync")
	}
	_, _ = p.Commit()
	if got := p.Generation(); got != 11 {
		t.Fatalf("commit after sync=%d, want 11", got)
	}
}

func TestBankPublisherGenerationWrapUsesSerialOrdering(t *testing.T) {
	p := NewBankPublisher()
	p.generation.Store(1)
	p.SyncGeneration(^uint32(0))
	if got := p.Generation(); got != 1 {
		t.Fatalf("stale pre-wrap sync changed generation to %d", got)
	}
	p.generation.Store(^uint32(0))
	if got := p.AdvanceGeneration(); got != 1 {
		t.Fatalf("advance did not wrap to 1: %d", got)
	}
	p.SyncGeneration(2)
	if got := p.Generation(); got != 2 {
		t.Fatalf("post-wrap sync=%d, want 2", got)
	}
}
