package dns

import (
	"context"
	"testing"
)

func TestDNSExchangeAdmissionIsProcessWideAndBounded(t *testing.T) {
	leases := make([]struct{}, 0, cap(dnsExchangeSlots))
	for len(leases) < cap(dnsExchangeSlots) {
		if !acquireDNSExchange(context.Background()) {
			t.Fatal("unexpected admission failure")
		}
		leases = append(leases, struct{}{})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if acquireDNSExchange(ctx) {
		t.Fatal("admission exceeded the process-wide capacity")
	}
	for range leases {
		releaseDNSExchange()
	}
}

func TestDNSExchangePerConnectionBudgetIsBelowGlobalBudget(t *testing.T) {
	if dnsExchangeSlotsPerConnection < 1 || dnsExchangeSlotsPerConnection >= cap(dnsExchangeSlots) {
		t.Fatalf("invalid hierarchical DNS budget: per_connection=%d global=%d",
			dnsExchangeSlotsPerConnection, cap(dnsExchangeSlots))
	}
}
