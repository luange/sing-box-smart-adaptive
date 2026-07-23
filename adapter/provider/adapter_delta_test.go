package provider

import "testing"

func TestProviderOutboundDeltaCombinesAndExpiresCursor(t *testing.T) {
	provider := new(Adapter)
	provider.appendOutboundDeltaLocked([]string{"a", "b"}, nil)
	provider.appendOutboundDeltaLocked([]string{"c"}, []string{"a"})
	delta, ok := provider.OutboundDelta(0)
	if !ok || delta.Revision != 2 || len(delta.Upserts) != 2 || delta.Upserts[0] != "b" || delta.Upserts[1] != "c" || len(delta.Removes) != 1 || delta.Removes[0] != "a" {
		t.Fatalf("unexpected combined delta: ok=%t delta=%+v", ok, delta)
	}
	for index := 0; index < 65; index++ {
		provider.appendOutboundDeltaLocked([]string{"rolling"}, nil)
	}
	if _, ok = provider.OutboundDelta(0); ok {
		t.Fatal("expired provider delta cursor was accepted")
	}
}
