//go:build with_ebpf && (linux || android) && !cgo

package ebpf

import (
	"net/netip"
	"runtime"

	E "github.com/sagernet/sing/common/exceptions"
)

const SharedNetworkMapCapacity = 16384

type SharedNetworkBackend struct{}

type SharedNetworkRuntimeStats struct {
	IngressRedirects     uint64
	IngressBypass        uint64
	IngressDrops         uint64
	EgressRestores       uint64
	EgressReverseMisses  uint64
	TokenFailures        uint64
	RewriteFailures      uint64
	SocketAssignments    uint64
	SocketAssignFailures uint64
	FlowUpdateFailures   uint64
}

func PrepareSharedNetwork(
	*Backend,
	uint16,
	bool,
	bool,
	netip.Prefix,
	netip.Prefix,
	bool,
	bool,
	uint32,
) (*SharedNetworkBackend, error) {
	return nil, unsupportedSharedNetworkError()
}

func unsupportedSharedNetworkError() error {
	return E.New("shared-network eBPF is not supported on ", runtime.GOOS, "/", runtime.GOARCH, " in this build")
}

func (b *SharedNetworkBackend) Enable() error { return unsupportedSharedNetworkError() }
func (b *SharedNetworkBackend) UpdateInterfaceMAC(uint32, []byte) error {
	return unsupportedSharedNetworkError()
}
func (b *SharedNetworkBackend) DeleteInterfaceMAC(uint32) error { return nil }
func (b *SharedNetworkBackend) Disable() error                  { return nil }
func (b *SharedNetworkBackend) IngressProgramFD() int {
	return -1
}
func (b *SharedNetworkBackend) EgressProgramFD() int {
	return -1
}
func (b *SharedNetworkBackend) RuntimeStats() (SharedNetworkRuntimeStats, error) {
	return SharedNetworkRuntimeStats{}, unsupportedSharedNetworkError()
}
func (b *SharedNetworkBackend) RegisterListenerSocket(uint32, int) error {
	return unsupportedSharedNetworkError()
}
func (b *SharedNetworkBackend) LookupOriginal(uint8, netip.AddrPort, netip.AddrPort) (OriginalDestination, error) {
	return OriginalDestination{}, unsupportedSharedNetworkError()
}
func (b *SharedNetworkBackend) DeleteRedirect(uint8, netip.AddrPort, netip.AddrPort) error {
	return unsupportedSharedNetworkError()
}
func (b *SharedNetworkBackend) UpdateHostAddresses([]netip.Addr) error {
	return unsupportedSharedNetworkError()
}
func (b *SharedNetworkBackend) Close() error   { return nil }
func (b *SharedNetworkBackend) IsClosed() bool { return true }
