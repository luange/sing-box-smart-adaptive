package trafficfamily

import (
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

const defaultInheritanceTTL = 45 * time.Second

type Match struct {
	ID              string
	StrictAffinity  bool
	ParentCandidate bool
	InheritParent   bool
}

type recentParent struct {
	family    string
	expiresAt time.Time
}

// Resolver combines a deliberately small semantic catalog with process-local
// flow lineage. Unknown sites are classified automatically by registrable
// domain; encrypted payloads are never inspected.
type Resolver struct {
	access  sync.Mutex
	recent  map[string]recentParent
	lineage time.Duration
}

func NewResolver() *Resolver {
	return &Resolver{recent: make(map[string]recentParent), lineage: defaultInheritanceTTL}
}

func (r *Resolver) Resolve(host, client string, now time.Time) Match {
	match := Classify(host)
	if r == nil || client == "" {
		return withGenericSite(match, host)
	}
	r.access.Lock()
	defer r.access.Unlock()
	if match.InheritParent {
		if parent, loaded := r.recent[client]; loaded && parent.expiresAt.After(now) {
			match.ID = parent.family
			match.StrictAffinity = true
			return match
		}
	}
	if match.ParentCandidate {
		r.recent[client] = recentParent{family: match.ID, expiresAt: now.Add(r.lineage)}
	}
	if len(r.recent) > 4096 {
		for key, parent := range r.recent {
			if !parent.expiresAt.After(now) {
				delete(r.recent, key)
			}
		}
	}
	return withGenericSite(match, host)
}

func withGenericSite(match Match, host string) Match {
	if match.ID != "" {
		return match
	}
	host = normalizeHost(host)
	if host == "" {
		match.ID = "unknown"
		return match
	}
	identity, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		identity = host
	}
	match.ID = "site:" + identity
	return match
}

// Classify contains only semantic anchors whose cross-domain identity cannot
// be inferred safely from encrypted connection behavior alone.
func Classify(host string) Match {
	host = normalizeHost(host)
	switch {
	case domainMatches(host, "youtube.com", "youtu.be", "ytimg.com", "ggpht.com", "googlevideo.com", "youtube-nocookie.com"):
		return strictParent("youtube")
	case domainMatches(host, "gemini.google.com", "bard.google.com", "generativelanguage.googleapis.com"):
		return strictParent("gemini")
	case host == "api.openai.com" || domainMatches(host, "platform.openai.com"):
		return strictParent("openai_api")
	case domainMatches(host, "chatgpt.com", "openai.com", "oaistatic.com", "oaiusercontent.com", "openai.com.cdn.cloudflare.net", "oaistatic.com.cdn.cloudflare.net", "chatgpt.com.cdn.cloudflare.net"):
		return strictParent("chatgpt_web")
	case domainMatches(host, "claude.ai", "anthropic.com"):
		return strictParent("claude")
	case domainMatches(host, "telegram.org", "t.me", "telegram.me", "telegram.dog"):
		return strictParent("telegram")
	case domainMatches(host, "accounts.google.com", "oauth2.googleapis.com", "securetoken.googleapis.com", "pay.google.com", "payments.google.com", "payments.googleusercontent.com"):
		return strictParent("google_account")
	case domainMatches(host, "appleid.apple.com", "idmsa.apple.com", "appleid.cdn-apple.com", "aaplimg.com"):
		return strictParent("apple_account")
	case domainMatches(host, "login.microsoftonline.com", "login.live.com", "account.live.com", "msauth.net", "msftauth.net"):
		return strictParent("microsoft_account")
	case domainMatches(host, "challenges.cloudflare.com", "turnstile.cloudflare.com"):
		return Match{ID: "cloudflare_challenge", StrictAffinity: true, InheritParent: true}
	case domainMatches(host, "whatsapp.com", "whatsapp.net", "wa.me"):
		return strictParent("whatsapp")
	case domainMatches(host, "wechat.com", "wechatapp.com", "weixin.qq.com", "weixin.qq.com.cn"):
		return strictParent("wechat")
	case domainMatches(host, "discord.com", "discord.gg", "discordapp.com", "discordapp.net"):
		return strictParent("discord")
	case domainMatches(host, "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "gmail.com", "googlemail.com", "1e100.net"):
		return strictParent("google")
	default:
		return Match{}
	}
}

func strictParent(id string) Match {
	return Match{ID: id, StrictAffinity: true, ParentCandidate: true}
}

func normalizeHost(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}

func domainMatches(host string, domains ...string) bool {
	for _, domain := range domains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}
