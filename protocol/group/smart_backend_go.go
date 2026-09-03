//go:build !smart_zig

package group

// The reference Go state machine remains the default build.  Keeping this
// constructor nil makes the existing host implementation the single owner of
// selection state unless the release explicitly opts into smart_zig.
func newSmartPolicyBackend(_ smartPolicyBackendConfig) smartPolicyBackend { return nil }

// Non-Zig builds remain useful for upstream-compatible development and
// platforms where cgo is unavailable. Production release profiles enable
// smart_zig and make the Zig policy kernel mandatory instead.
func smartPolicyBackendRequired() bool { return false }

type smartPolicyBackendConfig struct {
	Exploration         float64
	SwitchMargin        float64
	SwitchConfirm       int
	SwitchConfirmWindow int64
	SwitchCooldown      int64
	SelectionMode       uint8
}
