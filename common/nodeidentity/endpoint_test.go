package nodeidentity

import "testing"

func TestCanonicalEndpointOptionsStripsNestedCredentials(t *testing.T) {
	value, err := CanonicalEndpointOptions(map[string]any{
		"server":   "example.com",
		"password": "hidden",
		"tls":      map[string]any{"headers": map[string]any{"authorization": "hidden"}, "server_name": "example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	result := value.(map[string]any)
	if _, ok := result["password"]; ok {
		t.Fatal("top-level credential was retained")
	}
	tls := result["tls"].(map[string]any)
	if _, ok := tls["headers"]; ok {
		t.Fatal("nested headers were retained")
	}
	if tls["server_name"] != "example.com" {
		t.Fatalf("endpoint field changed: %#v", tls["server_name"])
	}
}
