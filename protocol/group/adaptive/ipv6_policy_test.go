package adaptive

import (
	"testing"

	M "github.com/sagernet/sing/common/metadata"
)

func TestAIIPv6PolicyBlocksOnlyStrictAIIPv6(t *testing.T) {
	pool := &AdaptivePool{aiIPv6Policy: "block"}
	ipv6 := M.ParseSocksaddr("[2001:4860:4860::8888]:443")
	ipv4 := M.ParseSocksaddr("1.1.1.1:443")
	if !pool.blockAIIPv6(ServiceContext{ID: "chatgpt_web"}, ipv6) {
		t.Fatal("ChatGPT IPv6 was not blocked")
	}
	if !pool.blockAIIPv6(ServiceContext{ID: "cloudflare_challenge"}, ipv6) {
		t.Fatal("challenge IPv6 was not blocked")
	}
	if pool.blockAIIPv6(ServiceContext{ID: "youtube"}, ipv6) {
		t.Fatal("non-AI IPv6 was blocked")
	}
	if pool.blockAIIPv6(ServiceContext{ID: "chatgpt_web"}, ipv4) {
		t.Fatal("AI IPv4 was blocked")
	}
	if pool.aiIPv6Blocked.Load() != 2 {
		t.Fatalf("unexpected blocked counter: %d", pool.aiIPv6Blocked.Load())
	}
	pool.aiIPv6Policy = "allow"
	if pool.blockAIIPv6(ServiceContext{ID: "chatgpt_web"}, ipv6) {
		t.Fatal("allow policy blocked IPv6")
	}
}
