package v3

import (
	"net/netip"
	"time"
)

// DataplaneSink is the single kernel-facing publish surface for engine=v3.
// Lifecycle dual-writes MemoryBackend (tests/audit) and this sink (live TC maps).
// Implementations: common/ebpf.V3Backend via sharedNetwork.backend.
type DataplaneSink interface {
	PublishStaticDirect(prefixes []netip.Prefix, generation uint32, bank uint32) error
	MergeStaticDirect(prefix netip.Prefix) error
	PutDirectFlow(protocol uint8, source, destination netip.AddrPort, ttl time.Duration) error
	DeleteDirectFlow(protocol uint8, source, destination netip.AddrPort) error
	PublishDNSHint(addr netip.Addr, direct bool, evidence uint8, generation uint32, ttl time.Duration) error
	InvalidateFlowDirect() error
	PolicyGeneration() uint32
}
