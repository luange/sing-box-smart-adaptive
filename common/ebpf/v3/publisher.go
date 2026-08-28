package v3

import (
	"fmt"
	"net/netip"
	"time"
)

// FlowPublishRequest is produced after userspace route reaches a stable leaf.
type FlowPublishRequest struct {
	Client      netip.AddrPort
	Destination netip.AddrPort
	Protocol    uint8
	Verdict     Verdict
	// LeafIsBareDirect must be true for DIRECT — selector/smart never.
	LeafIsBareDirect bool
	PolicyID         uint32
	TTL              time.Duration
	TimeoutClass     string // "dns" | "quic" | "data" — for UDP TTL defaults
}

// FlowPair is forward + reverse keys for kernel write.
type FlowPair struct {
	Forward FlowKey
	Reverse FlowKey
	Value   FlowValue
}

// DefaultFlowTTL picks TCP/UDP TTL per design §9.
func DefaultFlowTTL(protocol uint8, class string, configured time.Duration) time.Duration {
	if configured > 0 {
		return configured
	}
	if protocol == ProtocolTCP {
		return 10 * time.Minute
	}
	switch class {
	case "dns":
		return 30 * time.Second
	case "quic":
		return 2 * time.Minute
	default:
		return 3 * time.Minute
	}
}

// BuildFlowPair validates and builds bidirectional flow entries.
func BuildFlowPair(req FlowPublishRequest, generation uint32, expireNs uint64) (FlowPair, error) {
	if !req.Client.IsValid() || !req.Destination.IsValid() {
		return FlowPair{}, fmt.Errorf("invalid addresses")
	}
	if req.Protocol != ProtocolTCP && req.Protocol != ProtocolUDP {
		return FlowPair{}, fmt.Errorf("unsupported protocol")
	}
	if req.Verdict == VerdictDirect && !req.LeafIsBareDirect {
		return FlowPair{}, fmt.Errorf("DIRECT requires bare direct leaf")
	}
	if req.Destination.Port() == 53 && req.Verdict == VerdictDirect {
		return FlowPair{}, fmt.Errorf("port 53 must not learn DIRECT flow")
	}

	family, saddr, err := addrBytes(req.Client.Addr())
	if err != nil {
		return FlowPair{}, err
	}
	dfamily, daddr, err := addrBytes(req.Destination.Addr())
	if err != nil {
		return FlowPair{}, err
	}
	if family != dfamily {
		return FlowPair{}, fmt.Errorf("address family mismatch")
	}

	conf := ConfidenceStrong
	src := SourceExactFlow
	reason := ReasonFlowDirect
	switch req.Verdict {
	case VerdictDirect:
		reason = ReasonFlowDirect
	case VerdictProxy:
		reason = ReasonFlowProxy
		conf = ConfidenceStrong
	case VerdictBlock:
		reason = ReasonFlowBlock
	case VerdictMustControl:
		reason = ReasonMustControl
		conf = ConfidenceNone
	default:
		return FlowPair{}, fmt.Errorf("invalid verdict")
	}

	value := FlowValue{
		Verdict:    uint8(req.Verdict),
		Source:     uint8(src),
		Confidence: conf,
		ReasonCode: uint16(reason),
		PolicyID:   req.PolicyID,
		Generation: generation,
		ExpiresNs:  expireNs,
	}
	fwd := FlowKey{
		Family:    family,
		Protocol:  req.Protocol,
		Direction: 0,
		SPort:     req.Client.Port(),
		DPort:     req.Destination.Port(),
		SAddr:     saddr,
		DAddr:     daddr,
	}
	// Reverse uses direction=0 with swapped 5-tuple so TC (direction=0 only) hits.
	rev := FlowKey{
		Family:    family,
		Protocol:  req.Protocol,
		Direction: 0,
		SPort:     req.Destination.Port(),
		DPort:     req.Client.Port(),
		SAddr:     daddr,
		DAddr:     saddr,
	}
	return FlowPair{Forward: fwd, Reverse: rev, Value: value}, nil
}

func addrBytes(addr netip.Addr) (family uint8, out [16]byte, err error) {
	addr = addr.Unmap()
	if addr.Is4() {
		a := addr.As4()
		copy(out[:4], a[:])
		return AFInet, out, nil
	}
	if addr.Is6() {
		return AFInet6, addr.As16(), nil
	}
	return 0, out, fmt.Errorf("invalid addr")
}

// MemoryBackend is a test double for kernel maps (no cgo).
type MemoryBackend struct {
	Control   Control
	Policy4   [2]map[LPM4Key]PolicyValue
	Policy6   [2]map[LPM6Key]PolicyValue
	Flows     map[FlowKey]FlowValue
	DNS       *DNSHintTable
	Publisher *BankPublisher
	Stats     [StatsCount]uint64
}

func NewMemoryBackend() *MemoryBackend {
	b := &MemoryBackend{
		Publisher: NewBankPublisher(),
		Flows:     make(map[FlowKey]FlowValue),
		DNS:       NewDNSHintTable(),
	}
	b.Policy4[0] = make(map[LPM4Key]PolicyValue)
	b.Policy4[1] = make(map[LPM4Key]PolicyValue)
	b.Policy6[0] = make(map[LPM6Key]PolicyValue)
	b.Policy6[1] = make(map[LPM6Key]PolicyValue)
	bank, gen := b.Publisher.Snapshot()
	b.Control = Control{
		ABIVersion:       ABIVersion,
		Enabled:          1,
		Flags:            FlagIPv4 | FlagIPv6 | FlagTCP | FlagUDP | FlagSocketAssign | FlagStaticPolicy | FlagExactFlow | FlagDNSHint | FlagFakeIP | FlagFailureProxy,
		ActiveBank:       bank,
		PolicyGeneration: gen,
	}
	return b
}

// PublishStatic performs inactive-bank fill + atomic commit.
func (b *MemoryBackend) PublishStatic(policies []CompiledPolicy) error {
	inactive, ok := b.Publisher.BeginCompile()
	if !ok {
		return fmt.Errorf("compile already in progress")
	}
	// Clear inactive bank then fill — never touch active.
	b.Policy4[inactive] = make(map[LPM4Key]PolicyValue)
	b.Policy6[inactive] = make(map[LPM6Key]PolicyValue)
	var count4, count6 int
	for _, p := range policies {
		if p.Prefix.Addr().Unmap().Is4() {
			count4++
		} else {
			count6++
		}
	}
	if count4 > MaxPolicyLPM || count6 > MaxPolicyLPM {
		b.Publisher.AbortCompile()
		return fmt.Errorf("static policy capacity exceeded: ipv4=%d ipv6=%d max=%d", count4, count6, MaxPolicyLPM)
	}
	// generation for entries is commit generation (current+1)
	nextGen := b.Publisher.Generation() + 1
	if nextGen == 0 {
		nextGen = 1
	}
	for _, p := range policies {
		p.Value.Generation = nextGen
		addr := p.Prefix.Addr().Unmap()
		if addr.Is4() {
			key, err := PrefixToLPM4(p.Prefix)
			if err != nil {
				b.Publisher.AbortCompile()
				return err
			}
			b.Policy4[inactive][key] = p.Value
			continue
		}
		key, err := PrefixToLPM6(p.Prefix)
		if err != nil {
			b.Publisher.AbortCompile()
			return err
		}
		b.Policy6[inactive][key] = p.Value
	}
	gen, bank := b.Publisher.Commit()
	b.Control.ActiveBank = bank
	b.Control.PolicyGeneration = gen
	b.Stats[25] = uint64(gen) // RELOAD_GENERATION index if aligned — best-effort
	return nil
}

// PublishFlow writes bidirectional flow verdicts.
func (b *MemoryBackend) PublishFlow(req FlowPublishRequest, nowNs uint64) error {
	ttl := DefaultFlowTTL(req.Protocol, req.TimeoutClass, req.TTL)
	expire := nowNs + uint64(ttl)
	if expire < nowNs {
		expire = ^uint64(0)
	}
	pair, err := BuildFlowPair(req, b.Control.PolicyGeneration, expire)
	if err != nil {
		return err
	}
	b.pruneFlows(nowNs)
	needed := 0
	if _, ok := b.Flows[pair.Forward]; !ok {
		needed++
	}
	if _, ok := b.Flows[pair.Reverse]; !ok {
		needed++
	}
	for len(b.Flows)+needed > DefaultFlowEntries {
		if !b.evictOldestFlow() {
			break
		}
	}
	b.Flows[pair.Forward] = pair.Value
	b.Flows[pair.Reverse] = pair.Value
	return nil
}

func (b *MemoryBackend) pruneFlows(nowNs uint64) {
	for key, value := range b.Flows {
		if value.ExpiresNs != 0 && value.ExpiresNs <= nowNs {
			delete(b.Flows, key)
		}
	}
}

func (b *MemoryBackend) evictOldestFlow() bool {
	var oldestKey FlowKey
	var oldest uint64
	loaded := false
	for key, value := range b.Flows {
		if !loaded || value.ExpiresNs < oldest || (value.ExpiresNs == oldest && flowKeyLess(key, oldestKey)) {
			oldestKey, oldest, loaded = key, value.ExpiresNs, true
		}
	}
	if !loaded {
		return false
	}
	delete(b.Flows, oldestKey)
	return true
}

func flowKeyLess(left, right FlowKey) bool {
	if left.Family != right.Family {
		return left.Family < right.Family
	}
	if left.Protocol != right.Protocol {
		return left.Protocol < right.Protocol
	}
	if left.SPort != right.SPort {
		return left.SPort < right.SPort
	}
	if left.DPort != right.DPort {
		return left.DPort < right.DPort
	}
	if left.SAddr != right.SAddr {
		for index := range left.SAddr {
			if left.SAddr[index] != right.SAddr[index] {
				return left.SAddr[index] < right.SAddr[index]
			}
		}
	}
	for index := range left.DAddr {
		if left.DAddr[index] != right.DAddr[index] {
			return left.DAddr[index] < right.DAddr[index]
		}
	}
	return false
}

// RevokeFlow removes both directions after a real proxy/route failure.
func (b *MemoryBackend) RevokeFlow(client, dest netip.AddrPort, protocol uint8) error {
	pair, err := BuildFlowPair(FlowPublishRequest{
		Client:           client,
		Destination:      dest,
		Protocol:         protocol,
		Verdict:          VerdictProxy,
		LeafIsBareDirect: false,
	}, b.Control.PolicyGeneration, 1)
	if err != nil {
		return err
	}
	delete(b.Flows, pair.Forward)
	delete(b.Flows, pair.Reverse)
	return nil
}

// LookupStatic finds destination /32 or /128 style exact match in active bank
// (tests use host routes; production LPM is longest-prefix in kernel).
func (b *MemoryBackend) LookupStatic(dest netip.Addr, protocol uint8, dport uint16) *PolicyValue {
	bank := b.Control.ActiveBank
	addr := dest.Unmap()
	if addr.Is4() {
		a := addr.As4()
		key := LPM4Key{PrefixLen: 32, Addr: a}
		if v, ok := b.Policy4[bank][key]; ok && v.Generation == b.Control.PolicyGeneration {
			if v.MatchProtocol != 0 && uint8(v.MatchProtocol) != protocol {
				return nil
			}
			if v.MatchDPortMin != 0 || v.MatchDPortMax != 0 {
				if dport < v.MatchDPortMin || dport > v.MatchDPortMax {
					return nil
				}
			}
			return &v
		}
		return nil
	}
	key := LPM6Key{PrefixLen: 128, Addr: addr.As16()}
	if v, ok := b.Policy6[bank][key]; ok && v.Generation == b.Control.PolicyGeneration {
		return &v
	}
	return nil
}

// LookupFlow returns active generation flow.
func (b *MemoryBackend) LookupFlow(key FlowKey) *FlowValue {
	v, ok := b.Flows[key]
	if !ok || v.Generation != b.Control.PolicyGeneration || v.ExpiresNs != 0 && v.ExpiresNs <= uint64(time.Now().UnixNano()) {
		return nil
	}
	return &v
}
