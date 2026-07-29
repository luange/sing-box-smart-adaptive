package adaptive

import (
	"errors"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"

	"golang.org/x/net/publicsuffix"
)

type PolicyMode string

const (
	ModeStrictAffinity PolicyMode = "strict-affinity"
	ModeAdaptive       PolicyMode = "adaptive"
	ModeLatency        PolicyMode = "latency"
	ModeBulk           PolicyMode = "bulk"
	ModeManual         PolicyMode = "manual"
)

type ServiceContext struct {
	ID         string
	AffinityID string
	Session    SessionKey
	Mode       PolicyMode
	Host       string
	Transport  string
}

type ServiceResolver struct {
	hasher      *IdentityHasher
	defaultMode PolicyMode
	access      sync.RWMutex
	overrides   map[string]ServiceOverride
}

type ServiceOverride struct {
	ServiceID string
	Mode      PolicyMode
	ExpiresAt time.Time
}

func NewServiceResolver(hasher *IdentityHasher, defaultMode PolicyMode) *ServiceResolver {
	if defaultMode == "" {
		defaultMode = ModeAdaptive
	}
	return &ServiceResolver{hasher: hasher, defaultMode: defaultMode, overrides: make(map[string]ServiceOverride)}
}

func (r *ServiceResolver) Resolve(metadata *adapter.InboundContext, destination M.Socksaddr, transport string) ServiceContext {
	host := destinationHost(metadata, destination)
	serviceID, mode := resolveServiceFamily(host, r.defaultMode)
	if override, loaded := r.override(serviceID, time.Now()); loaded {
		mode = override.Mode
	}
	clientScope := "default"
	if metadata != nil {
		var processID uint32
		if metadata.ProcessInfo != nil {
			processID = metadata.ProcessInfo.ProcessID
		}
		clientScope = strings.Join([]string{
			metadata.Inbound,
			metadata.Source.Addr.String(),
			metadata.User,
			strconv.FormatUint(uint64(processID), 10),
		}, "\x00")
	}
	return ServiceContext{
		ID:         serviceID,
		AffinityID: serviceAffinityFamily(serviceID),
		Session:    r.hasher.Session(clientScope, serviceAffinityFamily(serviceID)),
		Mode:       mode,
		Host:       host,
		Transport:  transport,
	}
}

func serviceAffinityFamily(serviceID string) string {
	switch serviceID {
	case "chatgpt_web", "claude", "gemini", "google_account", "apple_account", "microsoft_account", "cloudflare_challenge":
		return "browser_identity"
	default:
		return serviceID
	}
}

func (r *ServiceResolver) SetOverride(serviceID string, mode PolicyMode, ttl time.Duration, now time.Time) error {
	serviceID = strings.TrimSpace(serviceID)
	if serviceID == "" || len(serviceID) > 128 || strings.ContainsAny(serviceID, "?\n\r") || ttl < time.Minute || ttl > 24*time.Hour {
		return errors.New("adaptive service override is invalid")
	}
	if mode != ModeStrictAffinity && mode != ModeAdaptive && mode != ModeLatency && mode != ModeBulk {
		return errors.New("adaptive service override mode is invalid")
	}
	r.access.Lock()
	for key, current := range r.overrides {
		if !current.ExpiresAt.After(now) {
			delete(r.overrides, key)
		}
	}
	if len(r.overrides) >= 1024 {
		r.access.Unlock()
		return errors.New("adaptive service override capacity reached")
	}
	r.overrides[serviceID] = ServiceOverride{ServiceID: serviceID, Mode: mode, ExpiresAt: now.Add(ttl)}
	r.access.Unlock()
	return nil
}

func (r *ServiceResolver) ClearOverride(serviceID string) bool {
	r.access.Lock()
	_, loaded := r.overrides[serviceID]
	delete(r.overrides, serviceID)
	r.access.Unlock()
	return loaded
}

func (r *ServiceResolver) Overrides(now time.Time) []ServiceOverride {
	r.access.RLock()
	result := make([]ServiceOverride, 0, len(r.overrides))
	for _, override := range r.overrides {
		if override.ExpiresAt.After(now) {
			result = append(result, override)
		}
	}
	r.access.RUnlock()
	sort.Slice(result, func(i, j int) bool { return result[i].ServiceID < result[j].ServiceID })
	return result
}

func (r *ServiceResolver) override(serviceID string, now time.Time) (ServiceOverride, bool) {
	r.access.RLock()
	override, loaded := r.overrides[serviceID]
	r.access.RUnlock()
	return override, loaded && override.ExpiresAt.After(now)
}

func resolveServiceFamily(host string, defaultMode PolicyMode) (string, PolicyMode) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	switch {
	case domainMatches(host, "youtube.com", "youtu.be", "ytimg.com", "ggpht.com", "googlevideo.com", "youtube-nocookie.com"):
		return "youtube", ModeStrictAffinity
	case domainMatches(host, "gemini.google.com", "bard.google.com", "generativelanguage.googleapis.com"):
		return "gemini", ModeStrictAffinity
	case host == "api.openai.com" || domainMatches(host, "platform.openai.com"):
		return "openai_api", ModeStrictAffinity
	case domainMatches(host, "chatgpt.com", "openai.com", "oaistatic.com", "oaiusercontent.com", "openai.com.cdn.cloudflare.net", "oaistatic.com.cdn.cloudflare.net", "chatgpt.com.cdn.cloudflare.net"):
		return "chatgpt_web", ModeStrictAffinity
	case domainMatches(host, "claude.ai", "anthropic.com"):
		return "claude", ModeStrictAffinity
	case domainMatches(host, "telegram.org", "t.me", "telegram.me", "telegram.dog"):
		return "telegram", ModeStrictAffinity
	case domainMatches(host, "accounts.google.com", "oauth2.googleapis.com", "securetoken.googleapis.com", "pay.google.com", "payments.google.com", "payments.googleusercontent.com"):
		return "google_account", ModeStrictAffinity
	case domainMatches(host, "appleid.apple.com", "idmsa.apple.com", "appleid.cdn-apple.com", "aaplimg.com"):
		return "apple_account", ModeStrictAffinity
	case domainMatches(host, "login.microsoftonline.com", "login.live.com", "account.live.com", "msauth.net", "msftauth.net"):
		return "microsoft_account", ModeStrictAffinity
	case domainMatches(host, "challenges.cloudflare.com", "turnstile.cloudflare.com"):
		return "cloudflare_challenge", ModeStrictAffinity
	case domainMatches(host, "whatsapp.com", "whatsapp.net", "wa.me"):
		return "whatsapp", ModeStrictAffinity
	}
	if host == "" {
		return "unknown", defaultMode
	}
	identity, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		identity = host
	}
	return "site:" + identity, defaultMode
}

func destinationHost(metadata *adapter.InboundContext, destination M.Socksaddr) string {
	if metadata != nil {
		if metadata.Domain != "" {
			return metadata.Domain
		}
		if metadata.SniffHost != "" {
			return metadata.SniffHost
		}
		if metadata.Destination.IsFqdn() {
			return metadata.Destination.Fqdn
		}
	}
	if destination.IsFqdn() {
		return destination.Fqdn
	}
	if destination.Addr.IsValid() {
		return destination.Addr.String()
	}
	return ""
}

func domainMatches(host string, domains ...string) bool {
	for _, domain := range domains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}
