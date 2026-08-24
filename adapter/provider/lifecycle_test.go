package provider

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

func TestProviderLifecyclePauseAndConsumerCount(t *testing.T) {
	var provider Adapter
	if provider.ProviderPaused() {
		t.Fatal("provider must start unpaused")
	}
	provider.SetProviderPaused(true)
	if !provider.ProviderPaused() {
		t.Fatal("provider pause was not recorded")
	}
	handle := provider.RegisterCallback(func(string) error { return nil })
	if consumers := provider.ProviderConsumers(); consumers != 1 {
		t.Fatalf("unexpected consumer count: %d", consumers)
	}
	provider.UnregisterCallback(handle)
	if consumers := provider.ProviderConsumers(); consumers != 0 {
		t.Fatalf("consumer was not released: %d", consumers)
	}
	var _ adapter.ProviderLifecycleController = &provider
}
