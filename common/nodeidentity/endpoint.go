// Package nodeidentity contains the canonical identity rules shared by
// Smart and AdaptivePool. Keeping this in one package prevents the two group
// implementations from silently creating different endpoint profiles.
package nodeidentity

import (
	"encoding/json"
	"strings"
)

// CanonicalEndpointOptions converts typed outbound options to a JSON-shaped
// value and removes credentials and other per-subscription secrets. The
// returned value is safe to hash for endpoint-level probe deduplication.
func CanonicalEndpointOptions(input any) (any, error) {
	raw, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	var value any
	if err = json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	return StripEndpointCredentials(value), nil
}

// StripEndpointCredentials recursively removes fields that identify a
// credential rather than the network endpoint.
func StripEndpointCredentials(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, item := range typed {
			normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "-", "_"), " ", "_"))
			switch normalized {
			case "password", "uuid", "psk", "token", "secret", "private_key", "privatekey", "auth", "authorization", "headers":
				continue
			}
			result[key] = StripEndpointCredentials(item)
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for index, item := range typed {
			result[index] = StripEndpointCredentials(item)
		}
		return result
	default:
		return value
	}
}
