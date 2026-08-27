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
	"strings"

	"github.com/sagernet/sing-box/adapter"
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
		// Options are normally typed structs. Normalize through JSON first so the
		// credential filter also applies to nested typed fields.
		rawOptions, err := json.Marshal(outboundOptions.Options)
		if err != nil {
			continue
		}
		var normalizedOptions any
		if err = json.Unmarshal(rawOptions, &normalizedOptions); err != nil {
			continue
		}
		payload := map[string]any{
			"type":    outboundOptions.Type,
			"options": stripSmartEndpointCredentials(normalizedOptions),
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

func stripSmartEndpointCredentials(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, item := range typed {
			normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "-", "_"), " ", "_"))
			switch normalized {
			case "password", "uuid", "psk", "token", "secret", "private_key", "privatekey", "auth", "authorization", "headers":
				continue
			}
			result[key] = stripSmartEndpointCredentials(item)
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for index, item := range typed {
			result[index] = stripSmartEndpointCredentials(item)
		}
		return result
	default:
		return value
	}
}
