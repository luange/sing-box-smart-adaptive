//go:build !smart_zig || !cgo

package group

// The reference Go state machine remains the default build.  Keeping this
// constructor nil makes the existing host implementation the single owner of
// selection state unless the release explicitly opts into smart_zig.
func newSmartPolicyBackend(_ smartPolicyBackendConfig) smartPolicyBackend { return nil }

type smartPolicyBackendConfig struct {
	Exploration         float64
	SwitchMargin        float64
	SwitchConfirm       int
	SwitchConfirmWindow int64
	SwitchCooldown      int64
}
