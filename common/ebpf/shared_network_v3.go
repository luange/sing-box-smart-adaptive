//go:build with_ebpf && (linux || android) && cgo

package ebpf

/*
#cgo CFLAGS: -I${SRCDIR}/native -I${SRCDIR}/v3/kern
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include "singbox_ebpf.h"

static int singbox_ebpf_v3_prepare(
	const uint8_t *object,
	size_t object_size,
	uint32_t policy_lpm,
	uint32_t flow_entries,
	uint32_t dns_hints,
	struct sb_ebpf_v3_runtime *runtime,
	int *saved_errno) {
	int result = sb_ebpf_v3_prepare(object, object_size, policy_lpm, flow_entries, dns_hints, runtime);
	if (result != 0) *saved_errno = errno;
	return result;
}

static int singbox_ebpf_v3_close(struct sb_ebpf_v3_runtime *runtime, int *saved_errno) {
	int result = sb_ebpf_v3_close(runtime);
	if (result != 0) *saved_errno = errno;
	return result;
}
*/
import "C"

import (
	_ "embed"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"
	"golang.org/x/sys/unix"
)

//go:embed v3/kern/tc.bpf.o
var sharedNetworkV3Object []byte

// V3Backend is the engine=v3 TC dataplane and the sole kernel policy sink.
// All static/flow/DNS verdicts that affect TC must be written here.
type V3Backend struct {
	access   sync.RWMutex
	runtime  *C.struct_sb_ebpf_v3_runtime
	control  v3Control
	hostIPv4 []netip.Prefix
	hostIPv6 []netip.Prefix
	// lastStatic tracks the last full snapshot so inactive-bank rewrite can
	// delete removed keys (LPM_TRIE has no clear-all).
	lastStatic      []netip.Prefix
	originalDstLost atomic.Uint64
	flowEnabled     bool
}

type v3Control struct {
	ABIVersion       uint32
	Enabled          uint32
	Flags            uint32
	ActiveBank       uint32
	PolicyGeneration uint32
	RoutingMark      uint32
	Reserved0        uint16
	Reserved1        uint16
	Reserved2        uint32
}

type v3PolicyValue struct {
	Verdict       uint8
	Source        uint8
	Confidence    uint8
	Reserved0     uint8
	ReasonCode    uint16
	MatchProtocol uint16
	MatchDPortMin uint16
	MatchDPortMax uint16
	PolicyID      uint32
	Generation    uint32
}

type v3FlowKey struct {
	Family    uint8
	Protocol  uint8
	Direction uint8
	Reserved0 uint8
	SPort     uint16
	DPort     uint16
	SAddr     [16]byte
	DAddr     [16]byte
}

type v3FlowValue struct {
	Verdict    uint8
	Source     uint8
	Confidence uint8
	Reserved0  uint8
	ReasonCode uint16
	Reserved1  uint16
	PolicyID   uint32
	Generation uint32
	ExpiresNs  uint64
}

type v3DNSKey struct {
	Family    uint8
	Reserved0 uint8
	Reserved1 uint16
	Addr      [16]byte
}

type v3DNSValue struct {
	DirectRefs uint32
	ProxyRefs  uint32
	PolicyID   uint32
	Generation uint32
	ExpiresNs  uint64
	LastSeenNs uint64
	Evidence   uint8
	Reserved0  uint8
	Reserved1  uint16
	Reserved2  uint32
}

type v3RedirectKey struct {
	Family     uint8
	Protocol   uint8
	Reserved0  uint16
	ClientPort uint16
	DestPort   uint16
	ClientAddr [16]byte
	DestAddr   [16]byte
}

type v3RedirectValue struct {
	Family    uint8
	Protocol  uint8
	DestPort  uint16
	IfIndex   uint32
	DestAddr  [16]byte
	SourceMAC [6]byte
	Reserved  [2]byte
}

type v3LPM4 struct {
	PrefixLen uint32
	Addr      [4]byte
}

type v3LPM6 struct {
	PrefixLen uint32
	Addr      [16]byte
}

const (
	v3FlagIPv4         = 1 << 0
	v3FlagIPv6         = 1 << 1
	v3FlagTCP          = 1 << 2
	v3FlagUDP          = 1 << 3
	v3FlagDNSHijack    = 1 << 4
	v3FlagDropUDP443   = 1 << 5
	v3FlagSocketAssign = 1 << 6
	v3FlagStaticPolicy = 1 << 7
	v3FlagExactFlow    = 1 << 8
	v3FlagDNSHint      = 1 << 9
	v3FlagFakeIP       = 1 << 10
	v3FlagMACSource    = 1 << 11
	v3FlagFailureProxy = 1 << 12
)

const (
	v3VerdictDirect = 1
	v3SourceStatic  = 1
	v3SourceFlow    = 2
	v3SourceDNSWeak = 3
	v3SourceFakeIP  = 4
)

// PrepareSharedNetworkV3 loads the independent v3 TC object.
func PrepareSharedNetworkV3(
	enableTCP bool,
	enableUDP bool,
	enableIPv4 bool,
	enableIPv6 bool,
	hijackDNS bool,
	dropUDP443 bool,
	routingMark uint32,
	policyOffloadStatic bool,
	policyOffloadFlow bool,
	policyOffloadDNS bool,
	policyOffloadFakeIP bool,
	flowMaxEntries uint32,
) (*V3Backend, error) {
	if len(sharedNetworkV3Object) == 0 {
		return nil, E.New("missing embedded eBPF v3 object (run make -C common/ebpf generate on Linux)")
	}
	if routingMark == 0 {
		return nil, E.New("missing shared-network socket-assignment routing mark")
	}
	// Match inbound Prepare: large LPM/LRU maps need unlocked RLIMIT_MEMLOCK.
	memlockErr := raiseMemlockLimit()
	runtimeState := (*C.struct_sb_ebpf_v3_runtime)(C.calloc(1, C.size_t(C.sizeof_struct_sb_ebpf_v3_runtime)))
	if runtimeState == nil {
		return nil, E.New("allocate eBPF v3 runtime")
	}
	var savedErrno C.int
	result := C.singbox_ebpf_v3_prepare(
		(*C.uint8_t)(unsafe.Pointer(&sharedNetworkV3Object[0])),
		C.size_t(len(sharedNetworkV3Object)),
		C.uint32_t(16384),
		C.uint32_t(flowMaxEntries),
		C.uint32_t(8192),
		runtimeState,
		&savedErrno,
	)
	if result != 0 {
		C.free(unsafe.Pointer(runtimeState))
		prepareErr := eBPFOperationError("prepare eBPF v3 programs", syscall.Errno(savedErrno))
		if memlockErr != nil && (syscall.Errno(savedErrno) == unix.ENOMEM || syscall.Errno(savedErrno) == unix.EPERM || syscall.Errno(savedErrno) == unix.EACCES) {
			prepareErr = E.Cause(prepareErr, "memlock limit could not be removed: ", memlockErr)
		}
		return nil, prepareErr
	}
	_ = memlockErr
	b := &V3Backend{runtime: runtimeState, flowEnabled: policyOffloadFlow}
	b.control.ABIVersion = 1
	b.control.PolicyGeneration = 1
	b.control.ActiveBank = 0
	b.control.RoutingMark = routingMark
	b.control.Flags = v3FlagSocketAssign | v3FlagFailureProxy
	if enableIPv4 {
		b.control.Flags |= v3FlagIPv4
	}
	if enableIPv6 {
		b.control.Flags |= v3FlagIPv6
	}
	if enableTCP {
		b.control.Flags |= v3FlagTCP
	}
	if enableUDP {
		b.control.Flags |= v3FlagUDP
	}
	if hijackDNS {
		b.control.Flags |= v3FlagDNSHijack
	}
	if dropUDP443 {
		b.control.Flags |= v3FlagDropUDP443
	}
	if policyOffloadStatic {
		b.control.Flags |= v3FlagStaticPolicy
	}
	if policyOffloadFlow {
		b.control.Flags |= v3FlagExactFlow
	}
	if policyOffloadDNS {
		b.control.Flags |= v3FlagDNSHint
	}
	if policyOffloadFakeIP {
		b.control.Flags |= v3FlagFakeIP
	}
	if err := b.writeControl(false); err != nil {
		_ = b.Close()
		return nil, E.Cause(err, "seed eBPF v3 control")
	}
	return b, nil
}

func (b *V3Backend) writeControl(enabled bool) error {
	if b == nil || b.runtime == nil {
		return osErrClosed
	}
	ctrl := b.control
	ctrl.Enabled = 0
	if enabled {
		ctrl.Enabled = 1
	}
	key := uint32(0)
	if err := updateMap(int(b.runtime.control_map_fd), unsafe.Pointer(&key), unsafe.Pointer(&ctrl)); err != nil {
		return err
	}
	b.control.Enabled = ctrl.Enabled
	return nil
}

func (b *V3Backend) WriteControlV3(enabled bool, flags uint32, activeBank, generation, routingMark uint32) error {
	if b == nil {
		return osErrClosed
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return osErrClosed
	}
	if generation == 0 {
		generation = 1
	}
	b.control.Flags = flags
	b.control.ActiveBank = activeBank & 1
	b.control.PolicyGeneration = generation
	if routingMark != 0 {
		b.control.RoutingMark = routingMark
	}
	return b.writeControl(enabled)
}

func (b *V3Backend) RegisterListenerSocket(key uint32, fd int) error {
	if b == nil || key >= 4 || fd < 0 {
		return E.New("invalid v3 listener socket")
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return osErrClosed
	}
	value := uint64(fd)
	return updateMapWithFlags(int(b.runtime.listener_map_fd), unsafe.Pointer(&key), unsafe.Pointer(&value), 0)
}

func (b *V3Backend) SetFlowDirect(enabled bool) error {
	if b == nil {
		return osErrClosed
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return osErrClosed
	}
	b.flowEnabled = enabled
	if enabled {
		b.control.Flags |= v3FlagExactFlow
	} else {
		b.control.Flags &^= v3FlagExactFlow
	}
	return b.writeControl(b.control.Enabled != 0)
}

func (b *V3Backend) PutDirectFlow(protocol uint8, source, destination netip.AddrPort, ttl time.Duration) error {
	if b == nil {
		return osErrClosed
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	fwd, rev, err := makeV3FlowPair(protocol, source, destination)
	if err != nil {
		return err
	}
	expires, err := monotonicExpireNs(ttl)
	if err != nil {
		return err
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil || !b.flowEnabled {
		return osErrClosed
	}
	value := v3FlowValue{
		Verdict:    v3VerdictDirect,
		Source:     v3SourceFlow,
		Confidence: 2,
		ReasonCode: 2, // flow_direct
		Generation: b.control.PolicyGeneration,
		ExpiresNs:  expires,
	}
	if err = updateMap(int(b.runtime.flow_map_fd), unsafe.Pointer(&fwd), unsafe.Pointer(&value)); err != nil {
		return E.Cause(err, "update v3 flow forward")
	}
	if err = updateMap(int(b.runtime.flow_map_fd), unsafe.Pointer(&rev), unsafe.Pointer(&value)); err != nil {
		return E.Cause(err, "update v3 flow reverse")
	}
	return nil
}

func (b *V3Backend) DeleteDirectFlow(protocol uint8, source, destination netip.AddrPort) error {
	if b == nil {
		return osErrClosed
	}
	fwd, rev, err := makeV3FlowPair(protocol, source, destination)
	if err != nil {
		return err
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return osErrClosed
	}
	_ = deleteMap(int(b.runtime.flow_map_fd), unsafe.Pointer(&fwd))
	_ = deleteMap(int(b.runtime.flow_map_fd), unsafe.Pointer(&rev))
	return nil
}

// makeV3FlowPair builds forward + reverse keys both with direction=0.
// TC looks up direction=0 only; reverse is the on-wire swapped 5-tuple.
func makeV3FlowPair(protocol uint8, source, destination netip.AddrPort) (v3FlowKey, v3FlowKey, error) {
	var fwd, rev v3FlowKey
	fwd.Protocol = protocol
	fwd.Direction = 0
	fwd.SPort = source.Port()
	fwd.DPort = destination.Port()
	if err := putAddress(&fwd.Family, &fwd.SAddr, source.Addr()); err != nil {
		return fwd, rev, err
	}
	var fam uint8
	if err := putAddress(&fam, &fwd.DAddr, destination.Addr()); err != nil {
		return fwd, rev, err
	}
	if fam != fwd.Family {
		return fwd, rev, E.New("v3 flow family mismatch")
	}
	rev.Family = fwd.Family
	rev.Protocol = protocol
	rev.Direction = 0
	rev.SPort = destination.Port()
	rev.DPort = source.Port()
	rev.SAddr = fwd.DAddr
	rev.DAddr = fwd.SAddr
	return fwd, rev, nil
}

func (b *V3Backend) InvalidateFlowDirect() error {
	if b == nil {
		return osErrClosed
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return osErrClosed
	}
	b.control.PolicyGeneration++
	if b.control.PolicyGeneration == 0 {
		b.control.PolicyGeneration = 1
	}
	// Also bump reload counter for soak observability.
	idx := uint32(25) // SB_V3_STAT_RELOAD_GENERATION
	var cur uint64
	_ = lookupMap(int(b.runtime.stats_map_fd), unsafe.Pointer(&idx), unsafe.Pointer(&cur))
	cur++
	_ = updateMap(int(b.runtime.stats_map_fd), unsafe.Pointer(&idx), unsafe.Pointer(&cur))
	return b.writeControl(b.control.Enabled != 0)
}

func (b *V3Backend) PolicyGeneration() uint32 {
	if b == nil {
		return 0
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.control.PolicyGeneration
}

// V3Stats reads the kernel reason counter array (SB_V3_STAT_* indices).
func (b *V3Backend) V3Stats() (stats []uint64, generation uint32, activeBank uint32) {
	if b == nil {
		return nil, 0, 0
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return nil, 0, 0
	}
	const n = 32 // SB_V3_STATS_COUNT
	stats = make([]uint64, n)
	for i := uint32(0); i < n; i++ {
		var v uint64
		idx := i
		_ = lookupMap(int(b.runtime.stats_map_fd), unsafe.Pointer(&idx), unsafe.Pointer(&v))
		stats[i] = v
	}
	return stats, b.control.PolicyGeneration, b.control.ActiveBank & 1
}

func (b *V3Backend) Enable() error {
	if b == nil {
		return osErrClosed
	}
	b.access.Lock()
	defer b.access.Unlock()
	return b.writeControl(true)
}

func (b *V3Backend) Disable() error {
	if b == nil {
		return nil
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return nil
	}
	return b.writeControl(false)
}

func (b *V3Backend) UpdateInterfaceMAC(ifIndex uint32, hardwareAddress []byte) error {
	// v3 source MAC policy is optional; interface MAC table not required for socket_assign.
	_ = ifIndex
	_ = hardwareAddress
	return nil
}

func (b *V3Backend) DeleteInterfaceMAC(ifIndex uint32) error {
	_ = ifIndex
	return nil
}

func (b *V3Backend) IngressProgramFD() int {
	if b == nil {
		return -1
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return -1
	}
	return int(b.runtime.ingress_prog_fd)
}

func (b *V3Backend) EgressProgramFD() int {
	return -1
}

func (b *V3Backend) RuntimeStats() (SharedNetworkRuntimeStats, error) {
	if b == nil {
		return SharedNetworkRuntimeStats{}, osErrClosed
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return SharedNetworkRuntimeStats{}, osErrClosed
	}
	// Map v3 reason counters onto the shared stats surface for soak logs.
	read := func(idx uint32) uint64 {
		var v uint64
		_ = lookupMap(int(b.runtime.stats_map_fd), unsafe.Pointer(&idx), unsafe.Pointer(&v))
		return v
	}
	staticDirect := read(0)
	flowDirect := read(1)
	fakeIPDirect := read(2)
	dnsHintDirect := read(3)
	mapMiss := read(5)
	parseFail := read(7)
	skOK := read(8)
	skFail := read(9)
	security := read(13)
	return SharedNetworkRuntimeStats{
		// First-packet + learned + DNS/FakeIP kernel DIRECT (design §14).
		IngressBypass:        staticDirect + flowDirect + fakeIPDirect + dnsHintDirect + security,
		SocketAssignments:    skOK,
		SocketAssignFailures: skFail,
		ParseFailures:        parseFail,
		PolicyBypass:         staticDirect + fakeIPDirect + dnsHintDirect,
		FallbackOpen:         mapMiss,
		EstablishedBypass:    read(14),
		OriginalDstLost:      b.originalDstLost.Load(),
	}, nil
}

func (b *V3Backend) LookupOriginal(protocol uint8, client, redirect netip.AddrPort) (OriginalDestination, error) {
	return b.lookupOriginal(protocol, client, redirect, false)
}

func (b *V3Backend) TakeOriginal(protocol uint8, client, redirect netip.AddrPort) (OriginalDestination, error) {
	return b.lookupOriginal(protocol, client, redirect, true)
}

func (b *V3Backend) lookupOriginal(protocol uint8, client, redirect netip.AddrPort, del bool) (OriginalDestination, error) {
	if b == nil {
		return OriginalDestination{}, osErrClosed
	}
	key, err := makeV3RedirectKey(protocol, client, redirect)
	if err != nil {
		return OriginalDestination{}, err
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return OriginalDestination{}, osErrClosed
	}
	var value v3RedirectValue
	if err = lookupMap(int(b.runtime.redirect_map_fd), unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
		b.originalDstLost.Add(1)
		return OriginalDestination{}, E.Cause(err, "lookup v3 original destination")
	}
	if del {
		_ = deleteMap(int(b.runtime.redirect_map_fd), unsafe.Pointer(&key))
	}
	addr, err := addrFromFamily(value.Family, value.DestAddr)
	if err != nil {
		return OriginalDestination{}, err
	}
	return OriginalDestination{
		Destination:    netip.AddrPortFrom(addr, value.DestPort),
		IngressIfIndex: value.IfIndex,
	}, nil
}

func makeV3RedirectKey(protocol uint8, client, dest netip.AddrPort) (v3RedirectKey, error) {
	var key v3RedirectKey
	key.Protocol = protocol
	key.ClientPort = client.Port()
	key.DestPort = dest.Port()
	if err := putAddress(&key.Family, &key.ClientAddr, client.Addr()); err != nil {
		return key, err
	}
	var fam uint8
	if err := putAddress(&fam, &key.DestAddr, dest.Addr()); err != nil {
		return key, err
	}
	if fam != key.Family {
		return key, E.New("v3 redirect family mismatch")
	}
	return key, nil
}

func addrFromFamily(family uint8, raw [16]byte) (netip.Addr, error) {
	switch family {
	case addressFamilyIPv4:
		return netip.AddrFrom4([4]byte(raw[:4])), nil
	case addressFamilyIPv6:
		return netip.AddrFrom16(raw), nil
	default:
		return netip.Addr{}, E.New("invalid family")
	}
}

func (b *V3Backend) DeleteRedirect(protocol uint8, client, redirect netip.AddrPort) error {
	if b == nil {
		return osErrClosed
	}
	key, err := makeV3RedirectKey(protocol, client, redirect)
	if err != nil {
		return err
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return osErrClosed
	}
	err = deleteMap(int(b.runtime.redirect_map_fd), unsafe.Pointer(&key))
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	return err
}

func (b *V3Backend) UpdateHostAddresses(addresses []netip.Addr) error {
	if b == nil {
		return osErrClosed
	}
	ipv4, ipv6 := compileSharedHostPrefixes(addresses)
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return osErrClosed
	}
	if err := replaceBypassCIDRPolicyMap(int(b.runtime.host6_map_fd), b.hostIPv6, ipv6); err != nil {
		return E.Cause(err, "update v3 host6")
	}
	if err := replaceBypassCIDRPolicyMap(int(b.runtime.host4_map_fd), b.hostIPv4, ipv4); err != nil {
		_ = replaceBypassCIDRPolicyMap(int(b.runtime.host6_map_fd), ipv6, b.hostIPv6)
		return E.Cause(err, "update v3 host4")
	}
	b.hostIPv4, b.hostIPv6 = ipv4, ipv6
	return nil
}

// PublishStaticDirect writes DIRECT prefixes into the inactive bank and commits
// with a new policy_generation (design §7.1 double-buffer).
// Removed prefixes from the previous snapshot are deleted from the inactive bank
// before commit so LPM capacity does not grow without bound across reloads.
func (b *V3Backend) PublishStaticDirect(prefixes []netip.Prefix, generation uint32, bank uint32) error {
	if b == nil {
		return osErrClosed
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return osErrClosed
	}
	if generation == 0 {
		generation = b.control.PolicyGeneration + 1
		if generation == 0 {
			generation = 1
		}
	}
	inactive := uint32(1 - (b.control.ActiveBank & 1))
	if bank <= 1 {
		// bank arg is advisory; always fill the true inactive bank.
		_ = bank
	}
	fd4 := int(b.runtime.policy4_bank0_fd)
	fd6 := int(b.runtime.policy6_bank0_fd)
	if inactive == 1 {
		fd4 = int(b.runtime.policy4_bank1_fd)
		fd6 = int(b.runtime.policy6_bank1_fd)
	}

	next := normalizePrefixSnapshot(prefixes)
	nextSet := make(map[netip.Prefix]struct{}, len(next))
	for _, p := range next {
		nextSet[p] = struct{}{}
	}
	// Drop keys present in last snapshot but not in the new one.
	for _, old := range b.lastStatic {
		if _, keep := nextSet[old]; keep {
			continue
		}
		_ = deleteV3PolicyPrefix(fd4, fd6, old)
	}
	for _, prefix := range next {
		if err := writeV3PolicyPrefix(fd4, fd6, prefix, generation); err != nil {
			return err
		}
	}
	b.lastStatic = next
	b.control.ActiveBank = inactive
	b.control.PolicyGeneration = generation
	return b.writeControl(b.control.Enabled != 0)
}

// MergeStaticDirect installs one DIRECT prefix into the *active* bank using the
// current generation. Used by dns_prefill / route promote so first-packet DIRECT
// works without invalidating exact-flow entries.
func (b *V3Backend) MergeStaticDirect(prefix netip.Prefix) error {
	if b == nil {
		return osErrClosed
	}
	prefix = prefix.Masked()
	if !prefix.IsValid() {
		return E.New("invalid static prefix")
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return osErrClosed
	}
	active := b.control.ActiveBank & 1
	fd4 := int(b.runtime.policy4_bank0_fd)
	fd6 := int(b.runtime.policy6_bank0_fd)
	if active == 1 {
		fd4 = int(b.runtime.policy4_bank1_fd)
		fd6 = int(b.runtime.policy6_bank1_fd)
	}
	if err := writeV3PolicyPrefix(fd4, fd6, prefix, b.control.PolicyGeneration); err != nil {
		return err
	}
	// Keep lastStatic coherent for the next full publish delete pass.
	found := false
	for _, p := range b.lastStatic {
		if p == prefix {
			found = true
			break
		}
	}
	if !found {
		b.lastStatic = append(b.lastStatic, prefix)
	}
	return nil
}

func normalizePrefixSnapshot(prefixes []netip.Prefix) []netip.Prefix {
	if len(prefixes) == 0 {
		return nil
	}
	seen := make(map[netip.Prefix]struct{}, len(prefixes))
	out := make([]netip.Prefix, 0, len(prefixes))
	for _, p := range prefixes {
		p = p.Masked()
		if !p.IsValid() {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

func writeV3PolicyPrefix(fd4, fd6 int, prefix netip.Prefix, generation uint32) error {
	prefix = prefix.Masked()
	addr := prefix.Addr().Unmap()
	value := v3PolicyValue{
		Verdict:    v3VerdictDirect,
		Source:     v3SourceStatic,
		Confidence: 2,
		ReasonCode: 1,
		Generation: generation,
	}
	if addr.Is4() {
		a := addr.As4()
		key := v3LPM4{PrefixLen: uint32(prefix.Bits()), Addr: a}
		return updateMap(fd4, unsafe.Pointer(&key), unsafe.Pointer(&value))
	}
	if addr.Is6() {
		key := v3LPM6{PrefixLen: uint32(prefix.Bits()), Addr: addr.As16()}
		return updateMap(fd6, unsafe.Pointer(&key), unsafe.Pointer(&value))
	}
	return E.New("invalid policy prefix family")
}

func deleteV3PolicyPrefix(fd4, fd6 int, prefix netip.Prefix) error {
	prefix = prefix.Masked()
	addr := prefix.Addr().Unmap()
	if addr.Is4() {
		a := addr.As4()
		key := v3LPM4{PrefixLen: uint32(prefix.Bits()), Addr: a}
		err := deleteMap(fd4, unsafe.Pointer(&key))
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	if addr.Is6() {
		key := v3LPM6{PrefixLen: uint32(prefix.Bits()), Addr: addr.As16()}
		err := deleteMap(fd6, unsafe.Pointer(&key))
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	return nil
}

func (b *V3Backend) PublishDNSHint(addr netip.Addr, direct bool, evidence uint8, generation uint32, ttl time.Duration) error {
	if b == nil {
		return osErrClosed
	}
	if ttl <= 0 {
		ttl = time.Minute
	}
	var key v3DNSKey
	a := addr.Unmap()
	if a.Is4() {
		key.Family = addressFamilyIPv4
		v4 := a.As4()
		copy(key.Addr[:4], v4[:])
	} else if a.Is6() {
		key.Family = addressFamilyIPv6
		key.Addr = a.As16()
	} else {
		return E.New("invalid dns hint address")
	}
	expires, err := monotonicExpireNs(ttl)
	if err != nil {
		return err
	}
	now, err := monotonicExpireNs(0)
	if err != nil {
		return err
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return osErrClosed
	}
	if generation == 0 {
		generation = b.control.PolicyGeneration
		if generation == 0 {
			generation = 1
		}
	}
	var cur v3DNSValue
	_ = lookupMap(int(b.runtime.dns_hint_map_fd), unsafe.Pointer(&key), unsafe.Pointer(&cur))
	if cur.Generation != generation {
		cur = v3DNSValue{Generation: generation, Evidence: evidence}
	}
	if direct {
		cur.DirectRefs++
	} else {
		cur.ProxyRefs++
	}
	// Conflict isolation (design §8.2): both refs → weak, never DIRECT in TC.
	if cur.ProxyRefs > 0 && cur.DirectRefs > 0 {
		cur.Evidence = 3 // weak
	} else if evidence > cur.Evidence {
		cur.Evidence = evidence
	}
	cur.ExpiresNs = expires
	cur.LastSeenNs = now
	cur.Generation = generation
	return updateMap(int(b.runtime.dns_hint_map_fd), unsafe.Pointer(&key), unsafe.Pointer(&cur))
}

func (b *V3Backend) Close() error {
	if b == nil {
		return nil
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return nil
	}
	_ = b.writeControl(false)
	var savedErrno C.int
	result := C.singbox_ebpf_v3_close(b.runtime, &savedErrno)
	C.free(unsafe.Pointer(b.runtime))
	b.runtime = nil
	if result != 0 {
		return eBPFOperationError("close eBPF v3 runtime", syscall.Errno(savedErrno))
	}
	return nil
}

func (b *V3Backend) IsClosed() bool {
	if b == nil {
		return true
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.runtime == nil
}

// No-op stubs so SharedNetworkBackend (v2) satisfies SharedDataplane.
func (b *SharedNetworkBackend) PublishStaticDirect(prefixes []netip.Prefix, generation uint32, bank uint32) error {
	return nil
}
func (b *SharedNetworkBackend) MergeStaticDirect(prefix netip.Prefix) error { return nil }
func (b *SharedNetworkBackend) PublishDNSHint(addr netip.Addr, direct bool, evidence uint8, generation uint32, ttl time.Duration) error {
	return nil
}
func (b *SharedNetworkBackend) WriteControlV3(enabled bool, flags uint32, activeBank, generation, routingMark uint32) error {
	return nil
}
func (b *SharedNetworkBackend) PolicyGeneration() uint32 { return 0 }
func (b *SharedNetworkBackend) V3Stats() ([]uint64, uint32, uint32) {
	return nil, 0, 0
}
func (b *SharedNetworkBackend) DeleteDirectFlow(protocol uint8, source, destination netip.AddrPort) error {
	// v2 has no per-tuple delete; generation bump via InvalidateFlowDirect is the revoke path.
	_ = protocol
	_ = source
	_ = destination
	return nil
}
