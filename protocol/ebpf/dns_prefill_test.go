//go:build with_ebpf && (linux || android)

package ebpf

import "testing"

func TestDNSPrefillAdmissionIsBounded(t *testing.T) {
	var inbound Inbound

	if !inbound.acquireDNSPrefillSlot() || !inbound.acquireDNSPrefillSlot() {
		t.Fatal("first two prefill workers should be admitted")
	}
	if inbound.acquireDNSPrefillSlot() {
		t.Fatal("prefill admission exceeded its worker bound")
	}
	if got := inbound.dnsPrefillQueueDrops.Load(); got != 1 {
		t.Fatalf("unexpected queue-drop count: %d", got)
	}

	inbound.releaseDNSPrefillWorker()
	if !inbound.acquireDNSPrefillSlot() {
		t.Fatal("a worker slot should be reusable after release")
	}
	inbound.releaseDNSPrefillWorker()
	inbound.releaseDNSPrefillWorker()

	inbound.dnsPrefillClosed.Store(true)
	if inbound.acquireDNSPrefillSlot() {
		t.Fatal("closed prefill admission accepted new work")
	}
}
