package clashapi

import "testing"

func TestSmartUpdateDefaultsToPersistentSelection(t *testing.T) {
	if useTemporarySmartOverride(UpdateProxyRequest{Name: "node"}) {
		t.Fatal("ordinary Clash PUT unexpectedly became a temporary override")
	}
	temporary := true
	if !useTemporarySmartOverride(UpdateProxyRequest{Name: "node", Temporary: &temporary}) {
		t.Fatal("explicit temporary override was not recognized")
	}
	if useTemporarySmartOverride(UpdateProxyRequest{Name: "node", Temporary: &temporary, Persistent: true}) {
		t.Fatal("persistent flag did not override temporary compatibility field")
	}
}
