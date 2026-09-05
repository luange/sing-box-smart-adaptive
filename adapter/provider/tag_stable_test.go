package provider

import (
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestUniqueProviderTagStableAcrossReloads(t *testing.T) {
	seen1 := map[string]bool{"airport/hk": true}
	id := providerOutboundIdentity(option.Outbound{Type: "trojan", Tag: "hk", Options: struct{ Server string }{Server: "1.2.3.4"}})
	tag1 := uniqueProviderTag("airport/hk", id, seen1)
	seen1[tag1] = true

	seen2 := map[string]bool{"airport/hk": true}
	tag2 := uniqueProviderTag("airport/hk", id, seen2)
	if tag1 != tag2 {
		t.Fatalf("stable rename drifted: %q vs %q", tag1, tag2)
	}
	if tag1 == "airport/hk" {
		t.Fatal("expected a distinct rename when base is taken")
	}
}

func TestProviderOutboundIdentityDiffersByOptions(t *testing.T) {
	a := providerOutboundIdentity(option.Outbound{Type: "trojan", Tag: "n", Options: struct{ Server string }{Server: "a"}})
	b := providerOutboundIdentity(option.Outbound{Type: "trojan", Tag: "n", Options: struct{ Server string }{Server: "b"}})
	if a == b {
		t.Fatal("different servers must fingerprint differently")
	}
}
