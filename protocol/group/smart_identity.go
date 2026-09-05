package group

// Smart probe identities are deliberately derived from the structured
// provider options when available.  Subscription providers commonly append a
// numeric suffix to otherwise identical nodes; using the runtime tag as the
// probe key makes every copy run its own health check and defeats the shared
// probe registry.  Credentials remain excluded so a password/UUID rotation
// does not create a second endpoint profile.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/nodeidentity"
	"github.com/sagernet/sing-box/option"
)

func (s *Smart) probeIdentityLocked(candidate adapter.Outbound) string {
	if candidate == nil {
		return ""
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
		// Normalize typed options once; the shared helper also applies the
		// credential filter to nested fields.
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
		h := sha256.New()
		_, _ = h.Write([]byte("sing-box/smart-endpoint/v1\x00"))
		_, _ = h.Write(raw)
		return "endpoint:" + hex.EncodeToString(h.Sum(nil))
	}
	// Static outbounds and legacy providers without structured options still
	// get a stable identity; retaining the tag avoids accidental cross-node
	// coalescing when there is no trustworthy endpoint description.
	return candidate.Type() + "\x00" + candidate.Tag()
}
