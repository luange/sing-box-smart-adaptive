package adaptive

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestServiceResolverBindsYouTubeCrossDomainSession(t *testing.T) {
	resolver := NewServiceResolver(testIdentityHasher(t), ModeAdaptive)
	metadata := &adapter.InboundContext{
		Inbound: "mixed-in",
		Source:  M.ParseSocksaddr("192.168.0.10:12345"),
	}
	control := resolver.Resolve(metadata, M.ParseSocksaddr("www.youtube.com:443"), N.NetworkTCP)
	media := resolver.Resolve(metadata, M.ParseSocksaddr("r1---sn.example.googlevideo.com:443"), N.NetworkUDP)
	image := resolver.Resolve(metadata, M.ParseSocksaddr("i.ytimg.com:443"), N.NetworkTCP)
	avatar := resolver.Resolve(metadata, M.ParseSocksaddr("yt3.ggpht.com:443"), N.NetworkTCP)
	if control.ID != "youtube" || media.ID != "youtube" || image.ID != "youtube" || avatar.ID != "youtube" {
		t.Fatalf("YouTube domains split across services: %q %q %q %q", control.ID, media.ID, image.ID, avatar.ID)
	}
	if control.Session != media.Session || control.Session != image.Session || control.Session != avatar.Session {
		t.Fatal("YouTube TCP/UDP domains did not share one session lease")
	}
	if control.Mode != ModeStrictAffinity {
		t.Fatalf("YouTube did not use strict affinity: %s", control.Mode)
	}
}

func TestServiceResolverSecurityAndMessagingFamilies(t *testing.T) {
	resolver := NewServiceResolver(testIdentityHasher(t), ModeAdaptive)
	client := &adapter.InboundContext{Inbound: "US-in", Source: M.ParseSocksaddr("192.168.0.10:1000")}
	tests := map[string]string{
		"accounts.google.com": "google_account", "payments.google.com": "google_account",
		"challenges.cloudflare.com": "cloudflare_challenge", "web.whatsapp.com": "whatsapp", "mmg.whatsapp.net": "whatsapp",
	}
	for host, expected := range tests {
		if got := resolver.Resolve(client, M.ParseSocksaddr(host+":443"), N.NetworkTCP); got.ID != expected || got.Mode != ModeStrictAffinity {
			t.Fatalf("service family mismatch host=%s got=%+v", host, got)
		}
	}
}

func TestServiceResolverFakeIPAndQUICMetadataPriority(t *testing.T) {
	resolver := NewServiceResolver(testIdentityHasher(t), ModeAdaptive)
	metadata := &adapter.InboundContext{
		Inbound: "US-in", Source: M.ParseSocksaddr("192.168.0.10:1000"), FakeIP: true,
		Domain: "r1.googlevideo.com", SniffHost: "unrelated.example", Destination: M.ParseSocksaddr("198.18.0.1:443"),
	}
	if got := resolver.Resolve(metadata, metadata.Destination, N.NetworkUDP); got.ID != "youtube" {
		t.Fatalf("FakeIP reverse domain did not win: %+v", got)
	}
	metadata.Domain = ""
	metadata.SniffHost = "api.openai.com"
	metadata.Protocol = "quic"
	if got := resolver.Resolve(metadata, metadata.Destination, N.NetworkUDP); got.ID != "openai_api" || got.Transport != N.NetworkUDP {
		t.Fatalf("QUIC sniff host did not determine service: %+v", got)
	}
}

func TestServiceResolverTemporaryOverrideExpires(t *testing.T) {
	resolver := NewServiceResolver(testIdentityHasher(t), ModeAdaptive)
	now := time.Unix(1_700_000_000, 0)
	if err := resolver.SetOverride("youtube", ModeBulk, time.Minute, now); err != nil {
		t.Fatal(err)
	}
	if override, loaded := resolver.override("youtube", now.Add(30*time.Second)); !loaded || override.Mode != ModeBulk {
		t.Fatalf("temporary override was not active: %+v loaded=%v", override, loaded)
	}
	if _, loaded := resolver.override("youtube", now.Add(2*time.Minute)); loaded {
		t.Fatal("expired temporary override remained active")
	}
	if err := resolver.SetOverride("youtube", PolicyMode("invalid"), time.Minute, now); err == nil {
		t.Fatal("invalid override mode was accepted")
	}
}

func TestServiceResolverSeparatesGoogleServiceFamiliesAndClients(t *testing.T) {
	resolver := NewServiceResolver(testIdentityHasher(t), ModeAdaptive)
	firstClient := &adapter.InboundContext{Inbound: "mixed-in", Source: M.ParseSocksaddr("192.168.0.10:1000")}
	secondClient := &adapter.InboundContext{Inbound: "mixed-in", Source: M.ParseSocksaddr("192.168.0.11:1000")}
	youtube := resolver.Resolve(firstClient, M.ParseSocksaddr("youtube.com:443"), N.NetworkTCP)
	gemini := resolver.Resolve(firstClient, M.ParseSocksaddr("gemini.google.com:443"), N.NetworkTCP)
	otherClient := resolver.Resolve(secondClient, M.ParseSocksaddr("youtube.com:443"), N.NetworkTCP)
	if youtube.Session == gemini.Session {
		t.Fatal("YouTube and Gemini incorrectly shared a lease")
	}
	if youtube.Session == otherClient.Session {
		t.Fatal("different clients incorrectly shared a strict-affinity lease")
	}
}

func TestServiceResolverSeparatesOpenAIAPIFromChatGPTWeb(t *testing.T) {
	resolver := NewServiceResolver(testIdentityHasher(t), ModeAdaptive)
	client := &adapter.InboundContext{Inbound: "mixed-in", Source: M.ParseSocksaddr("192.168.0.10:1000")}
	api := resolver.Resolve(client, M.ParseSocksaddr("api.openai.com:443"), N.NetworkTCP)
	web := resolver.Resolve(client, M.ParseSocksaddr("chatgpt.com:443"), N.NetworkTCP)
	static := resolver.Resolve(client, M.ParseSocksaddr("cdn.oaistatic.com:443"), N.NetworkTCP)
	if api.ID != "openai_api" || web.ID != "chatgpt_web" || static.ID != "chatgpt_web" {
		t.Fatalf("OpenAI service families were not separated: api=%q web=%q static=%q", api.ID, web.ID, static.ID)
	}
	if api.Session == web.Session || web.Session != static.Session {
		t.Fatal("OpenAI API and ChatGPT web lease boundaries are incorrect")
	}
}
