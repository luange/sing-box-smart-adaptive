package trafficfamily

import (
	"testing"
	"time"
)

func TestSemanticAnchors(t *testing.T) {
	tests := map[string]string{
		"chatgpt.com": "chatgpt_web", "auth.openai.com": "chatgpt_web",
		"api.openai.com": "openai_api", "claude.ai": "claude",
		"r1.googlevideo.com": "youtube", "gemini.google.com": "gemini",
		"mmg.whatsapp.net": "whatsapp", "sglong.wechat.com": "wechat",
		"gateway.discord.gg": "discord", "accounts.google.com": "google_account",
	}
	for host, expected := range tests {
		if got := Classify(host); got.ID != expected || !got.StrictAffinity {
			t.Fatalf("host=%s got=%+v want=%s", host, got, expected)
		}
	}
}

func TestUnknownSiteClassifiesAutomatically(t *testing.T) {
	resolver := NewResolver()
	if got := resolver.Resolve("img.assets.example.co.uk", "client", time.Now()); got.ID != "site:example.co.uk" || got.StrictAffinity {
		t.Fatalf("unexpected automatic site family: %+v", got)
	}
}

func TestChallengeInheritsRecentParent(t *testing.T) {
	resolver := NewResolver()
	now := time.Now()
	resolver.Resolve("chatgpt.com", "client-a", now)
	if got := resolver.Resolve("challenges.cloudflare.com", "client-a", now.Add(time.Second)); got.ID != "chatgpt_web" {
		t.Fatalf("challenge did not inherit product family: %+v", got)
	}
	if got := resolver.Resolve("challenges.cloudflare.com", "client-b", now.Add(time.Second)); got.ID != "cloudflare_challenge" {
		t.Fatalf("unrelated client inherited another client lineage: %+v", got)
	}
	if got := resolver.Resolve("challenges.cloudflare.com", "client-a", now.Add(time.Minute)); got.ID != "cloudflare_challenge" {
		t.Fatalf("expired lineage remained active: %+v", got)
	}
}
