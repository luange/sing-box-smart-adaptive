package v3

import (
	"fmt"
	"net/netip"
	"sync"
	"time"

	ebpfv3 "github.com/sagernet/sing-box/common/ebpf/v3"
	"github.com/sagernet/sing-box/option"
)

// Lifecycle owns v3 control-plane state for one ebpf inbound.
// MemoryBackend is the pure model (tests + audit). BindSink attaches the live
// kernel dataplane so learn/publish/DNS never diverge from TC maps.
type Lifecycle struct {
	mu sync.Mutex

	options option.EBPFSharedNetworkOptions
	backend *ebpfv3.MemoryBackend
	sink    DataplaneSink

	flowTTL time.Duration
}

// NewLifecycle constructs control-plane state. Does not attach TC.
func NewLifecycle(options option.EBPFSharedNetworkOptions, flowTTL time.Duration) (*Lifecycle, error) {
	normalized, err := NormalizeSharedNetwork(options)
	if err != nil {
		return nil, err
	}
	if !IsV3(normalized) {
		return nil, fmt.Errorf("lifecycle requires engine=v3")
	}
	if flowTTL <= 0 {
		flowTTL = 10 * time.Minute
	}
	return &Lifecycle{
		options: normalized,
		backend: ebpfv3.NewMemoryBackend(),
		flowTTL: flowTTL,
	}, nil
}

// BindSink attaches the live kernel publisher. Call once after V3Backend prepare.
func (l *Lifecycle) BindSink(sink DataplaneSink) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sink = sink
}

// Backend exposes the in-process map model (tests + future kernel sync).
func (l *Lifecycle) Backend() *ebpfv3.MemoryBackend {
	if l == nil {
		return nil
	}
	return l.backend
}

// SyncPolicyGeneration keeps the audit model aligned with a generation that
// was committed by the live kernel publisher.  Callers must not mutate the
// Backend control block directly: LearnFlow, ObserveDNS, reload and Close all
// share this lock.
func (l *Lifecycle) SyncPolicyGeneration(generation uint32) {
	if l == nil || generation == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.backend != nil {
		l.backend.Publisher.SyncGeneration(generation)
		l.backend.Control.PolicyGeneration = generation
	}
}

// Options returns normalized shared_network options.
func (l *Lifecycle) Options() option.EBPFSharedNetworkOptions {
	if l == nil {
		return option.EBPFSharedNetworkOptions{}
	}
	return l.options
}

// ControlFlags builds kernel control flags from options.
func ControlFlags(options option.EBPFSharedNetworkOptions, enableIPv4, enableIPv6, enableTCP, enableUDP, dnsHijack bool, routingMark uint32) uint32 {
	var flags uint32
	if enableIPv4 {
		flags |= ebpfv3.FlagIPv4
	}
	if enableIPv6 {
		flags |= ebpfv3.FlagIPv6
	}
	if enableTCP {
		flags |= ebpfv3.FlagTCP
	}
	if enableUDP {
		flags |= ebpfv3.FlagUDP
	}
	if dnsHijack {
		flags |= ebpfv3.FlagDNSHijack
	}
	if options.DropUDP443 != nil && *options.DropUDP443 {
		flags |= ebpfv3.FlagDropUDP443
	}
	if options.DataPlane == "" || options.DataPlane == "socket_assign" {
		flags |= ebpfv3.FlagSocketAssign
	}
	flags |= ebpfv3.FlagFailureProxy
	po := options.PolicyOffload
	if po.Enabled {
		if po.StaticRules {
			flags |= ebpfv3.FlagStaticPolicy
		}
		if po.ExactFlowLearning {
			flags |= ebpfv3.FlagExactFlow
		}
		switch po.DNSIPHint {
		case "safe", "strong":
			flags |= ebpfv3.FlagDNSHint
		}
		if po.FakeIP {
			flags |= ebpfv3.FlagFakeIP
		}
		if po.MACSourcePolicy {
			flags |= ebpfv3.FlagMACSource
		}
	}
	_ = routingMark
	return flags
}

// ApplyControlFlags refreshes backend control flag bits without flipping generation.
func (l *Lifecycle) ApplyControlFlags(enableIPv4, enableIPv6, enableTCP, enableUDP, dnsHijack bool, routingMark uint32) {
	if l == nil || l.backend == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.backend.Control.Flags = ControlFlags(l.options, enableIPv4, enableIPv6, enableTCP, enableUDP, dnsHijack, routingMark)
	l.backend.Control.RoutingMark = routingMark
	l.backend.Control.ABIVersion = ebpfv3.ABIVersion
	l.backend.Control.Enabled = 1
}

// PublishStaticRules compiles and double-buffers static DIRECT/PROXY/BLOCK sinks.
// When a kernel sink is bound, only DIRECT destination prefixes are pushed today
// (PROXY/BLOCK static sinks land in a later compiler expansion).
func (l *Lifecycle) PublishStaticRules(inputs []ebpfv3.CompileInput) (accepted int, rejected int, err error) {
	if l == nil || l.backend == nil {
		return 0, 0, fmt.Errorf("nil lifecycle")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.options.PolicyOffload.Enabled || !l.options.PolicyOffload.StaticRules {
		return 0, len(inputs), nil
	}
	compiled, rej, err := ebpfv3.CompileStatic(inputs, l.backend.Control.PolicyGeneration)
	if err != nil {
		return 0, 0, err
	}
	// Validate without mutating the userspace mirror before committing the
	// kernel bank. This keeps generation/bank state aligned when a sink rejects
	// the update (for example because a map write or control update failed).
	if err := l.backend.ValidateStatic(compiled); err != nil {
		return 0, 0, err
	}
	if l.sink != nil {
		direct := make([]netip.Prefix, 0, len(compiled))
		for _, c := range compiled {
			if c.Value.Verdict == uint8(ebpfv3.VerdictDirect) {
				direct = append(direct, c.Prefix)
			}
		}
		if err := l.sink.PublishStaticDirect(direct, 0, 0); err != nil {
			return len(compiled), len(rej), err
		}
	}
	if err := l.backend.PublishStatic(compiled); err != nil {
		return 0, 0, err
	}
	return len(compiled), len(rej), nil
}

// LearnFlow publishes exact-flow verdict after userspace bare-direct route.
func (l *Lifecycle) LearnFlow(client, dest netip.AddrPort, protocol uint8, bareDirect bool, now time.Time) error {
	if l == nil || l.backend == nil {
		return fmt.Errorf("nil lifecycle")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.options.PolicyOffload.Enabled || !l.options.PolicyOffload.ExactFlowLearning {
		return nil
	}
	if !bareDirect {
		return nil
	}
	if err := l.backend.PublishFlow(ebpfv3.FlowPublishRequest{
		Client:           client,
		Destination:      dest,
		Protocol:         protocol,
		Verdict:          ebpfv3.VerdictDirect,
		LeafIsBareDirect: true,
		TTL:              l.flowTTL,
	}, uint64(now.UnixNano())); err != nil {
		return err
	}
	if l.sink != nil {
		return l.sink.PutDirectFlow(protocol, client, dest, l.flowTTL)
	}
	return nil
}

// RevokeFlow clears a learned flow after real failure.
func (l *Lifecycle) RevokeFlow(client, dest netip.AddrPort, protocol uint8) error {
	if l == nil || l.backend == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = l.backend.RevokeFlow(client, dest, protocol)
	if l.sink != nil {
		return l.sink.DeleteDirectFlow(protocol, client, dest)
	}
	return nil
}

// ObserveDNS records DNS/FakeIP evidence with conflict isolation and mirrors
// into the kernel DNS hint map when a sink is bound.
func (l *Lifecycle) ObserveDNS(addr netip.Addr, direct bool, evidence uint8, ttl time.Duration, now time.Time) {
	if l == nil || l.backend == nil || l.backend.DNS == nil {
		return
	}
	if !l.options.PolicyOffload.Enabled {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	family := uint8(ebpfv3.AFInet)
	var raw [16]byte
	a := addr.Unmap()
	if a.Is4() {
		v4 := a.As4()
		copy(raw[:4], v4[:])
	} else if a.Is6() {
		family = ebpfv3.AFInet6
		raw = a.As16()
	} else {
		return
	}
	if ttl <= 0 {
		ttl = time.Minute
	}
	key := ebpfv3.DNSIPKey{Family: family, Addr: raw}
	expire := uint64(now.Add(ttl).UnixNano())
	l.backend.DNS.Observe(key, direct, evidence, 0, l.backend.Control.PolicyGeneration, expire, uint64(now.UnixNano()))
	if l.sink != nil {
		_ = l.sink.PublishDNSHint(addr, direct, evidence, 0, ttl)
	}
}

// InvalidateGeneration bumps policy generation on memory + kernel sinks so
// stale exact-flow / DNS hints miss until re-learned (interface/route reload).
func (l *Lifecycle) InvalidateGeneration() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.backend != nil {
		l.backend.Control.PolicyGeneration++
		if l.backend.Control.PolicyGeneration == 0 {
			l.backend.Control.PolicyGeneration = 1
		}
	}
	if l.sink != nil {
		return l.sink.InvalidateFlowDirect()
	}
	return nil
}

// Close releases control-plane state (kernel detach is a separate step on Linux).
func (l *Lifecycle) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.backend != nil {
		l.backend.Control.Enabled = 0
	}
	return nil
}
