//go:build with_ebpf && (linux || android) && cgo

package ebpf

import (
	"net/netip"
	"time"
)

// SharedDataplane is the TC shared-network backend surface used by protocol/ebpf.
// v2 and v3 both implement this so engine selection stays outside TC attach code.
//
// Control-plane contract (design §3/§7): every learn/publish/invalidate path that
// affects packet verdicts must go through this interface — never a parallel
// in-memory model that is not synced to kernel maps.
type SharedDataplane interface {
	RegisterListenerSocket(key uint32, fd int) error
	SetFlowDirect(enabled bool) error
	PutDirectFlow(protocol uint8, source, destination netip.AddrPort, ttl time.Duration) error
	DeleteDirectFlow(protocol uint8, source, destination netip.AddrPort) error
	InvalidateFlowDirect() error
	Enable() error
	Disable() error
	UpdateInterfaceMAC(ifIndex uint32, hardwareAddress []byte) error
	DeleteInterfaceMAC(ifIndex uint32) error
	IngressProgramFD() int
	EgressProgramFD() int
	RuntimeStats() (SharedNetworkRuntimeStats, error)
	LookupOriginal(protocol uint8, client, redirect netip.AddrPort) (OriginalDestination, error)
	TakeOriginal(protocol uint8, client, redirect netip.AddrPort) (OriginalDestination, error)
	DeleteRedirect(protocol uint8, client, redirect netip.AddrPort) error
	UpdateHostAddresses(addresses []netip.Addr) error
	// V3 policy surface (no-op on v2).
	// PublishStaticDirect replaces the inactive bank and commits (full snapshot).
	PublishStaticDirect(prefixes []netip.Prefix, generation uint32, bank uint32) error
	// MergeStaticDirect writes one DIRECT prefix into the *active* bank without
	// bumping generation (incremental promote / dns_prefill).
	MergeStaticDirect(prefix netip.Prefix) error
	PublishDNSHint(addr netip.Addr, direct bool, evidence uint8, generation uint32, ttl time.Duration) error
	WriteControlV3(enabled bool, flags uint32, activeBank, generation, routingMark uint32) error
	PolicyGeneration() uint32
	// V3Stats returns raw reason counters (index = SB_V3_STAT_*), generation, active bank.
	// v2 returns nil,0,0.
	V3Stats() (stats []uint64, generation uint32, activeBank uint32)
	Close() error
	IsClosed() bool
}

// Ensure compile-time conformance.
var (
	_ SharedDataplane = (*SharedNetworkBackend)(nil)
	_ SharedDataplane = (*V3Backend)(nil)
)
