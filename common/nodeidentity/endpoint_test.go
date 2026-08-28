package nodeidentity

import "testing"

func TestCanonicalEndpointOptionsStripsNestedCredentials(t *testing.T) {
	value, err := CanonicalEndpointOptions(map[string]any{
		"server":   "example.com",
		"password": "hidden",
		"tls":      map[string]any{"headers": map[string]any{"authorization": "hidden", "Host": "edge.example.com"}, "server_name": "example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	result := value.(map[string]any)
	if _, ok := result["password"]; ok {
		t.Fatal("top-level credential was retained")
	}
	tls := result["tls"].(map[string]any)
	headers, ok := tls["headers"].(map[string]any)
	if !ok {
		t.Fatal("routing headers were dropped")
	}
	if _, ok := headers["authorization"]; ok {
		t.Fatal("nested authorization header was retained")
	}
	if headers["Host"] != "edge.example.com" {
		t.Fatalf("routing Host header changed: %#v", headers["Host"])
	}
	if tls["server_name"] != "example.com" {
		t.Fatalf("endpoint field changed: %#v", tls["server_name"])
	}
}
