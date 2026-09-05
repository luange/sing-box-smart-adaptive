package group

import "testing"

// Every binary exposes its policy ownership in SmartStatus. This contract
// prevents a release build from silently changing from the Zig kernel to the
// duplicate Go selector when cgo, the static library, or an ABI changes.
func TestSmartPolicyBackendBuildContract(t *testing.T) {
	name := smartPolicyBackendName()
	if name == "" {
		t.Fatal("Smart policy backend name is empty")
	}
	if smartPolicyBackendRequired() && name == "go-reference" {
		t.Fatalf("required Smart build selected the Go reference backend: %q", name)
	}
	if !smartPolicyBackendRequired() && name != "go-reference" {
		t.Fatalf("optional Smart build selected unexpected backend %q", name)
	}
}
