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
		if current := l.backend.Control.PolicyGeneration; current != 0 && generation < current {
			return
		}
		l.backend.Control.PolicyGeneration = generation
		l.backend.Publisher.SyncGeneration(generation)
		l.backend.InvalidateGeneration(generation)
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

// ApplyControlFlags refreshes backend control flag bits without flipping
// generation. When a kernel sink is bound, the same flags are pushed into the
// live control map (WriteControlV3) so a reconfig cannot leave the kernel
// running a stale feature mask while the memory model moved on.
func (l *Lifecycle) ApplyControlFlags(enableIPv4, enableIPv6, enableTCP, enableUDP, dnsHijack bool, routingMark uint32) error {
	if l == nil || l.backend == nil {
		return fmt.Errorf("nil lifecycle")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	flags := ControlFlags(l.options, enableIPv4, enableIPv6, enableTCP, enableUDP, dnsHijack, routingMark)
	l.backend.Control.Flags = flags
	l.backend.Control.RoutingMark = routingMark
	l.backend.Control.ABIVersion = ebpfv3.ABIVersion
	l.backend.Control.Enabled = 1
	if l.sink != nil {
		bank, generation := l.backend.Publisher.Snapshot()
		return l.sink.WriteControlV3(true, flags, bank, generation, routingMark)
	}
	return nil
}

// PublishStaticRules compiles and double-buffers static DIRECT rules.  The v3
// dataplane intentionally has one direct fast-path sink; proxy/block/group
// rules remain userspace decisions and are reported as rejected instead of
// being counted as accepted while silently disappearing at the kernel boundary.
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
	direct := make([]ebpfv3.CompiledPolicy, 0, len(compiled))
	for _, policy := range compiled {
		// DataplaneSink.PublishStaticDirect intentionally accepts only a
		// destination prefix.  Publishing a protocol/port-scoped rule through
		// that surface would silently broaden it to all traffic for the prefix;
		// keep such rules in userspace instead of changing their semantics.
		if policy.Value.Verdict == uint8(ebpfv3.VerdictDirect) &&
			policy.Value.MatchProtocol == 0 &&
			policy.Value.MatchDPortMin == 0 && policy.Value.MatchDPortMax == 0 {
			direct = append(direct, policy)
		} else {
			rej = append(rej, ebpfv3.CompileInput{Destination: policy.Prefix, Verdict: ebpfv3.Verdict(policy.Value.Verdict), Kind: ebpfv3.RuleKindNeedsControl, PolicyID: policy.Value.PolicyID})
		}
	}
	directPrefixes := make([]netip.Prefix, 0, len(direct))
	for _, c := range direct {
		directPrefixes = append(directPrefixes, c.Prefix)
	}
	if l.sink != nil {
		if err := l.sink.PublishStaticDirect(directPrefixes, 0, 0); err != nil {
			return len(direct), len(rej), err
		}
	}
	if err := l.backend.PublishStatic(direct); err != nil {
		return 0, 0, err
	}
	return len(direct), len(rej), nil
}

// PublishMACSourcePolicies replaces the complete MAC-source identity
// snapshot in both control-plane representations. It is a no-op unless
// policy_offload.mac_source_policy is enabled, so the kernel flag and the
// publication surface stay consistent. Kernel publication happens first
// (the fail-closed side), then the memory model is committed.
func (l *Lifecycle) PublishMACSourcePolicies(entries []ebpfv3.MACPolicyEntry) error {
	if l == nil || l.backend == nil {
		return fmt.Errorf("nil lifecycle")
	}
	if !l.options.PolicyOffload.Enabled || !l.options.PolicyOffload.MACSourcePolicy {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.sink != nil {
		if err := l.sink.PublishMACPolicies(entries); err != nil {
			return err
		}
	}
	return l.backend.PublishMACPolicies(entries)
}

// PublishStaticDirect replaces the complete DIRECT prefix snapshot in both
// control-plane representations.  The protocol/ebpf parent already resolved
// these prefixes from its route and rule-set state, so there is no CompileInput
// to validate here.  Kernel publication happens first (the fail-closed side),
// then the memory model is committed with the same bank-flip semantics for
// tests, diagnostics, and later generation invalidation.
func (l *Lifecycle) PublishStaticDirect(prefixes []netip.Prefix) error {
	if l == nil || l.backend == nil {
		return fmt.Errorf("nil lifecycle")
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	normalized := make([]netip.Prefix, 0, len(prefixes))
	seen := make(map[netip.Prefix]struct{}, len(prefixes))
	policies := make([]ebpfv3.CompiledPolicy, 0, len(prefixes))
	for _, prefix := range prefixes {
		prefix = prefix.Masked()
		if !prefix.IsValid() {
			continue
		}
		if _, loaded := seen[prefix]; loaded {
			continue
		}
		seen[prefix] = struct{}{}
		normalized = append(normalized, prefix)
		policies = append(policies, ebpfv3.CompiledPolicy{
			Prefix: prefix,
			Value: ebpfv3.PolicyValue{
				Verdict:    uint8(ebpfv3.VerdictDirect),
				Source:     uint8(ebpfv3.SourceStatic),
				Confidence: ebpfv3.ConfidenceStrong,
				ReasonCode: uint16(ebpfv3.ReasonStaticDirect),
			},
		})
	}
	if l.sink != nil {
		if err := l.sink.PublishStaticDirect(normalized, 0, 0); err != nil {
			return err
		}
	}
	return l.backend.PublishStatic(policies)
}

// MergeStaticDirect publishes one learned DIRECT prefix to the active bank
// while keeping the kernel sink and in-process model in lockstep. It is a
// no-op when static policy offload is disabled because the TC program would
// not consult the policy bank in that mode.
func (l *Lifecycle) MergeStaticDirect(prefix netip.Prefix) error {
	if l == nil || l.backend == nil {
		return fmt.Errorf("nil lifecycle")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.options.PolicyOffload.Enabled || !l.options.PolicyOffload.StaticRules {
		return nil
	}
	if l.sink != nil {
		if err := l.sink.MergeStaticDirect(prefix); err != nil {
			return err
		}
	}
	return l.backend.MergeStaticDirect(prefix)
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
	request := ebpfv3.FlowPublishRequest{
		Client:           client,
		Destination:      dest,
		Protocol:         protocol,
		Verdict:          ebpfv3.VerdictDirect,
		LeafIsBareDirect: true,
		TTL:              l.flowTTL,
	}
	if l.sink != nil {
		if err := l.sink.PutDirectFlow(protocol, client, dest, l.flowTTL); err != nil {
			return err
		}
	}
	if err := l.backend.PublishFlow(request, uint64(now.UnixNano())); err != nil {
		return err
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
	if err := l.backend.RevokeFlow(client, dest, protocol); err != nil {
		return err
	}
	if l.sink != nil {
		return l.sink.DeleteDirectFlow(protocol, client, dest)
	}
	return nil
}

// ObserveDNS records DNS/FakeIP evidence with conflict isolation and mirrors
// into the kernel DNS hint map when a sink is bound.
func (l *Lifecycle) ObserveDNS(addr netip.Addr, direct bool, evidence uint8, ttl time.Duration, now time.Time) error {
	if l == nil || l.backend == nil || l.backend.DNS == nil {
		return nil
	}
	if !l.options.PolicyOffload.Enabled {
		return nil
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
		return nil
	}
	if ttl <= 0 {
		ttl = time.Minute
	}
	if now.IsZero() {
		now = time.Now()
	}
	key := ebpfv3.DNSIPKey{Family: family, Addr: raw}
	expire := uint64(now.Add(ttl).UnixNano())
	if l.sink != nil {
		if err := l.sink.PublishDNSHint(addr, direct, evidence, 0, ttl); err != nil {
			return err
		}
	}
	l.backend.DNS.Observe(key, direct, evidence, 0, l.backend.Control.PolicyGeneration, expire, uint64(now.UnixNano()))
	return nil
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
		l.backend.Publisher.SyncGeneration(l.backend.Control.PolicyGeneration)
		l.backend.InvalidateGeneration(l.backend.Control.PolicyGeneration)
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
