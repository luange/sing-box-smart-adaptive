package group

// Smart probe identities are deliberately derived from the structured
// provider options when available. Subscription providers commonly append a
// numeric suffix to otherwise identical nodes; using the runtime tag as the
// endpoint profile key makes every copy run its own health check and defeats
// the shared probe registry. Endpoint policy identity excludes credentials,
// while the separate health identity keeps authentication outcomes isolated.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/nodeidentity"
	"github.com/sagernet/sing-box/option"
)

func (s *Smart) probeIdentityLocked(candidate adapter.Outbound) string {
	endpoint, _ := s.probeIdentityPairLocked(candidate)
	return endpoint
}

// probeHealthIdentityLocked keeps credential/session outcomes separate while
// the endpoint identity remains shared for policy ranking. A bad UUID or
// password must not poison a duplicate line using the same server and port.
func (s *Smart) probeHealthIdentityLocked(candidate adapter.Outbound) string {
	_, health := s.probeIdentityPairLocked(candidate)
	return health
}

func (s *Smart) probeIdentityPairLocked(candidate adapter.Outbound) (string, string) {
	if candidate == nil {
		return "", ""
	}
	for _, provider := range s.providers {
		if provider == nil {
			continue
		}
		var outboundOptions option.Outbound
		var loaded bool
		if lookup, ok := provider.(adapter.ProviderOutboundOptionLookup); ok {
			outboundOptions, loaded = lookup.OutboundOption(candidate.Tag())
		} else if source, ok := provider.(adapter.ProviderOutboundOptions); ok {
			outboundOptions, loaded = source.OutboundOptions()[candidate.Tag()]
		}
		if !loaded || outboundOptions.Type == "" || outboundOptions.Options == nil {
			continue
		}
		// Normalize typed options once for the endpoint-level policy identity.
		normalizedOptions, err := nodeidentity.CanonicalEndpointOptions(outboundOptions.Options)
		if err != nil {
			continue
		}
		payload := map[string]any{
			"type":    outboundOptions.Type,
			"options": normalizedOptions,
		}
		raw, err := json.Marshal(payload)
		if err != nil {
			break
		}
		endpointHash := sha256.New()
		_, _ = endpointHash.Write([]byte("sing-box/smart-endpoint/v1\x00"))
		_, _ = endpointHash.Write(raw)
		// The full option payload is only hashed and never logged or exported.
		// It separates authentication outcomes without retaining credentials.
		fullRaw, fullErr := json.Marshal(outboundOptions.Options)
		if fullErr != nil {
			fullRaw = raw
		}
		healthHash := sha256.New()
		_, _ = healthHash.Write([]byte("sing-box/smart-health/v1\x00"))
		_, _ = healthHash.Write(fullRaw)
		return "endpoint:" + hex.EncodeToString(endpointHash.Sum(nil)), "health:" + hex.EncodeToString(healthHash.Sum(nil))
	}
	// Static outbounds and legacy providers without structured options still
	// get a stable identity; retaining the tag avoids accidental cross-node
	// coalescing when there is no trustworthy endpoint description.
	fallback := candidate.Type() + "\x00" + candidate.Tag()
	return fallback, fallback
}
