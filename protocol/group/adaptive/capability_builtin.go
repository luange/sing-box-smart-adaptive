package adaptive

import (
	"context"
	"errors"
	"sync"
	"time"
)

const builtinServiceTLSSourceID = "builtin-service-tls-v1"

type builtinServiceTarget struct {
	url        string
	capability ProbeCapability
}

var builtinAIServiceTargets = map[string]builtinServiceTarget{
	"youtube":       {url: "https://www.youtube.com/", capability: ProbeCapabilityTLS},
	"gemini":        {url: "https://www.google.com/", capability: ProbeCapabilityTLS},
	"openai_api":    {url: "https://api.openai.com/v1/models", capability: ProbeCapabilityAuthHTTP},
	"chatgpt_web":   {url: "https://chatgpt.com/", capability: ProbeCapabilityWebWAF},
	"claude":        {url: "https://api.anthropic.com/v1/models", capability: ProbeCapabilityAuthHTTP},
	"exit_identity": {url: "https://api.ipify.org/", capability: ProbeCapabilityExitIdentity},
}

// BuiltinYouTubeTLSTargetProvider supplies a non-secret service target. It is
// intentionally limited to TLS capability; signed media URLs remain under the
// manifest trust boundary used by range and payload probes.
type BuiltinYouTubeTLSTargetProvider struct {
	clock Clock

	access     sync.RWMutex
	generation uint64
	services   []string
	snapshots  map[string]*ProbeTargetSnapshot
}

func NewBuiltinYouTubeTLSTargetProvider(clock Clock) (*BuiltinYouTubeTLSTargetProvider, error) {
	if clock == nil {
		clock = realClock{}
	}
	provider := &BuiltinYouTubeTLSTargetProvider{clock: clock, services: []string{youtubeProbeServiceID}, snapshots: make(map[string]*ProbeTargetSnapshot)}
	if err := provider.Refresh(context.Background()); err != nil {
		return nil, err
	}
	return provider, nil
}

func NewBuiltinAIServiceTLSTargetProvider(clock Clock) (*BuiltinYouTubeTLSTargetProvider, error) {
	if clock == nil {
		clock = realClock{}
	}
	provider := &BuiltinYouTubeTLSTargetProvider{
		clock: clock, services: []string{"youtube", "gemini", "openai_api", "chatgpt_web", "claude"},
		snapshots: make(map[string]*ProbeTargetSnapshot),
	}
	if err := provider.Refresh(context.Background()); err != nil {
		return nil, err
	}
	return provider, nil
}

func NewBuiltinCapabilityTargetProvider(clock Clock, includeYouTube, includeAI, includeExitIdentity bool) (*BuiltinYouTubeTLSTargetProvider, error) {
	if clock == nil {
		clock = realClock{}
	}
	services := make([]string, 0, 6)
	if includeAI {
		services = append(services, "youtube", "gemini", "openai_api", "chatgpt_web", "claude")
	} else if includeYouTube {
		services = append(services, "youtube")
	}
	if includeExitIdentity {
		services = append(services, "exit_identity")
	}
	if len(services) == 0 {
		return nil, errors.New("adaptive builtin capability set is empty")
	}
	provider := &BuiltinYouTubeTLSTargetProvider{clock: clock, services: services, snapshots: make(map[string]*ProbeTargetSnapshot)}
	if err := provider.Refresh(context.Background()); err != nil {
		return nil, err
	}
	return provider, nil
}

func (p *BuiltinYouTubeTLSTargetProvider) ServiceIDs() []string {
	return append([]string(nil), p.services...)
}

func (p *BuiltinYouTubeTLSTargetProvider) Refresh(context.Context) error {
	if p == nil || p.clock == nil {
		return errors.New("adaptive builtin YouTube TLS provider is invalid")
	}
	now := p.clock.Now()
	p.access.Lock()
	defer p.access.Unlock()
	if len(p.snapshots) == len(p.services) {
		fresh := true
		for _, snapshot := range p.snapshots {
			fresh = fresh && snapshot.ExpiresAt.Sub(now) >= 24*time.Hour
		}
		if fresh {
			return nil
		}
	}
	p.generation++
	issuedAt := now.Add(-time.Minute)
	expiresAt := now.Add(7 * 24 * time.Hour)
	snapshots := make(map[string]*ProbeTargetSnapshot, len(p.services))
	for _, serviceID := range p.services {
		spec, loaded := builtinAIServiceTargets[serviceID]
		if !loaded {
			return errors.New("adaptive builtin service target is unknown")
		}
		target, err := NewProbeTarget(spec.url, p.generation, spec.capability, issuedAt, expiresAt, nil, nil)
		if err != nil {
			return err
		}
		snapshot, err := NewProbeTargetSnapshot(builtinServiceTLSSourceID, serviceID, p.generation, issuedAt, expiresAt, []ProbeTarget{target})
		if err != nil {
			return err
		}
		snapshots[serviceID] = snapshot
	}
	p.snapshots = snapshots
	return nil
}

func (p *BuiltinYouTubeTLSTargetProvider) Snapshot(_ context.Context, serviceID string) (*ProbeTargetSnapshot, error) {
	if p == nil {
		return nil, ErrProbeRunUnknown
	}
	p.access.RLock()
	snapshot := cloneProbeTargetSnapshot(p.snapshots[serviceID])
	p.access.RUnlock()
	if snapshot == nil {
		return nil, ErrProbeRunUnknown
	}
	return snapshot, nil
}
