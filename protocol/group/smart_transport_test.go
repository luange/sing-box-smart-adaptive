package group

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestSmartTransportKeyKeepsAddressFamiliesSeparate(t *testing.T) {
	v4 := M.ParseSocksaddr("192.0.2.10:443")
	v6 := M.ParseSocksaddr("[2001:db8::10]:443")
	if got := smartTransportKey(N.NetworkTCP, v4); got != "tcp/ipv4" {
		t.Fatalf("IPv4 transport key = %q", got)
	}
	if got := smartTransportKey(N.NetworkTCP, v6); got != "tcp/ipv6" {
		t.Fatalf("IPv6 transport key = %q", got)
	}
	if got := smartTransportKey(N.NetworkTCP, M.ParseSocksaddr("example.com:443")); got != "tcp" {
		t.Fatalf("domain transport key = %q, want aggregate tcp", got)
	}
	if got := smartTransportKey(N.NetworkUDP+"6", M.Socksaddr{}); got != "udp/ipv6" {
		t.Fatalf("explicit UDPv6 transport key = %q", got)
	}
	if got := smartTransportBase("tcp/ipv6"); got != N.NetworkTCP {
		t.Fatalf("family transport base = %q", got)
	}
}

func TestSmartUDPRequiredResponsePackets(t *testing.T) {
	if got := smartUDPRequiredResponsePackets(M.ParseSocksaddr("dns.example:53")); got != 1 {
		t.Fatalf("DNS packet threshold = %d, want 1", got)
	}
	if got := smartUDPRequiredResponsePackets(M.ParseSocksaddr("video.example:443")); got != 3 {
		t.Fatalf("QUIC packet threshold = %d, want 3", got)
	}
	if got := smartUDPRequiredResponsePackets(M.ParseSocksaddr("stun.example:3478")); got != 3 {
		t.Fatalf("STUN packet threshold = %d, want 3", got)
	}
}

func TestSmartPolicyStateABIIsAdditive(t *testing.T) {
	if got := smartPolicyState("suspect"); got != 3 {
		t.Fatalf("suspect ABI state = %d, want 3", got)
	}
	if got := smartPolicyState("open"); got != 4 {
		t.Fatalf("open ABI state = %d, want 4", got)
	}
	if got := smartPolicyState("half_open"); got != 5 {
		t.Fatalf("half-open ABI state = %d, want additive state 5", got)
	}
}

func TestSmartAddressFamilyHealthIsIndependent(t *testing.T) {
	store := newSmartStore(time.Hour, 3, time.Minute)
	now := time.Now()
	for range 3 {
		store.observeDial(now, "network", "site", "node", "tcp/ipv4", false, time.Second)
	}
	store.observeDial(now, "network", "site", "node", "tcp/ipv6", true, 30*time.Millisecond)
	v4 := store.estimate(now, "network", "site", "node", "tcp/ipv4", 3)
	v6 := store.estimate(now, "network", "site", "node", "tcp/ipv6", 3)
	if v4.State != "open" {
		t.Fatalf("IPv4 failure did not open only the IPv4 circuit: %+v", v4)
	}
	if v6.State == "open" || v6.Reliability <= v4.Reliability {
		t.Fatalf("IPv6 evidence was contaminated by IPv4 failures: v4=%+v v6=%+v", v4, v6)
	}
}

func TestSmartProbeBudgetPrefersUsedAndStaleCandidates(t *testing.T) {
	candidates := make([]adapter.Outbound, 8)
	for index := range candidates {
		candidates[index] = newSmartFakeOutbound("candidate-"+itoaSmall(index), nil)
	}
	smart := newTestSmart(candidates...)
	now := time.Now()
	for range 5 {
		smart.noteCandidateUse("candidate-7", now)
	}
	selected := smart.selectProbeCandidates(candidates, 4)
	if len(selected) != 4 {
		t.Fatalf("selected %d candidates, want 4", len(selected))
	}
	if selected[0].Tag() != "candidate-7" {
		t.Fatalf("most-used candidate was not prioritized: %s", selected[0].Tag())
	}
}

func TestSmartUseScoreDecaysWhenSelectingProbeCandidates(t *testing.T) {
	candidates := []adapter.Outbound{
		newSmartFakeOutbound("recent", nil),
		newSmartFakeOutbound("stale", nil),
		newSmartFakeOutbound("unused", nil),
	}
	smart := newTestSmart(candidates...)
	now := time.Now()
	smart.access.Lock()
	smart.useScores = map[string]smartUseScore{
		"recent": {Score: 1, LastUsed: now.Add(-5 * time.Minute)},
		"stale":  {Score: 100, LastUsed: now.Add(-smartUseScoreDecayWindow - time.Minute)},
	}
	smart.access.Unlock()
	selected := smart.selectProbeCandidates(candidates, 2)
	if selected[0].Tag() != "recent" {
		t.Fatalf("stale use score was not decayed before ranking: %q", selected[0].Tag())
	}
}

func TestSmartProbeBudgetDeduplicatesEndpointAliases(t *testing.T) {
	candidates := []adapter.Outbound{
		newSmartFakeOutbound("line-a", nil),
		newSmartFakeOutbound("line-a (2)", nil),
		newSmartFakeOutbound("line-b", nil),
		newSmartFakeOutbound("line-c", nil),
	}
	smart := newTestSmart(candidates...)
	setSmartCandidateIdentities(smart, map[string]string{
		"line-a":     "endpoint-a",
		"line-a (2)": "endpoint-a",
		"line-b":     "endpoint-b",
		"line-c":     "endpoint-c",
	})
	selected := smart.selectProbeCandidates(candidates, 3)
	if len(selected) != 3 {
		t.Fatalf("selected %d candidates, want 3 distinct endpoints", len(selected))
	}
	seen := make(map[string]struct{}, len(selected))
	for _, candidate := range selected {
		profileID := smart.candidateProfileID(candidate.Tag())
		if _, exists := seen[profileID]; exists {
			t.Fatalf("probe budget selected endpoint alias twice: %q", profileID)
		}
		seen[profileID] = struct{}{}
	}
}

func TestSmartUseScoreTracksTCPButNotUDP(t *testing.T) {
	candidate := newSmartFakeOutboundNetworks("node", []string{N.NetworkTCP, N.NetworkUDP}, nil)
	smart := newTestSmart(candidate)
	smart.markSelected(candidate, "network", "site", "site", "udp/ipv4", nil, 0, false)
	smart.access.RLock()
	if len(smart.useScores) != 0 {
		smart.access.RUnlock()
		t.Fatalf("UDP selection unexpectedly changed TCP use score: %+v", smart.useScores)
	}
	smart.access.RUnlock()
	smart.markSelected(candidate, "network", "site", "site", N.NetworkTCP, nil, 0, false)
	smart.access.RLock()
	defer smart.access.RUnlock()
	if usage := smart.useScores["node"]; usage.Score != 1 {
		t.Fatalf("TCP selection use score = %v, want 1", usage.Score)
	}
}
