package group

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
)

type smartIdentityProvider struct {
	adapter.Provider
	options map[string]option.Outbound
}

func (p *smartIdentityProvider) OutboundOption(tag string) (option.Outbound, bool) {
	value, ok := p.options[tag]
	return value, ok
}

func TestSmartProbeIdentitySharesCredentialVariants(t *testing.T) {
	provider := &smartIdentityProvider{options: map[string]option.Outbound{
		"node-1": {Type: "trojan", Options: map[string]any{"server": "edge.example", "server_port": 443, "password": "one", "tls": map[string]any{"server_name": "edge.example"}}},
		"node-2": {Type: "trojan", Options: map[string]any{"server": "edge.example", "server_port": 443, "password": "two", "tls": map[string]any{"server_name": "edge.example"}}},
		"node-3": {Type: "trojan", Options: map[string]any{"server": "other.example", "server_port": 443, "password": "two", "tls": map[string]any{"server_name": "other.example"}}},
	}}
	smart := &Smart{providers: map[string]adapter.Provider{"p": provider}}
	a := newSmartFakeOutbound("node-1", nil)
	b := newSmartFakeOutbound("node-2", nil)
	c := newSmartFakeOutbound("node-3", nil)
	if gotA, gotB := smart.probeIdentityLocked(a), smart.probeIdentityLocked(b); gotA != gotB {
		t.Fatalf("credential variants must share endpoint identity: %q != %q", gotA, gotB)
	}
	if gotA, gotC := smart.probeIdentityLocked(a), smart.probeIdentityLocked(c); gotA == gotC {
		t.Fatalf("different endpoints must not share identity: %q", gotA)
	}
}
