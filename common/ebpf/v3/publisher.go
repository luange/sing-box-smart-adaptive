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
	Control         Control
	Policy4         [2]map[LPM4Key]PolicyValue
	Policy6         [2]map[LPM6Key]PolicyValue
	Flows           map[FlowKey]FlowValue
	DNS             *DNSHintTable
	Publisher       *BankPublisher
	Stats           [StatsCount]uint64
	flowLimit       int
	nextFlowPruneNs uint64
}

func NewMemoryBackend() *MemoryBackend {
	b := &MemoryBackend{
		Publisher: NewBankPublisher(),
		Flows:     make(map[FlowKey]FlowValue),
		DNS:       NewDNSHintTable(),
		flowLimit: maxMemoryFlowEntries,
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
	// Build off to the side, then install the complete bank in one assignment;
	// a malformed prefix must not leave a partially refreshed inactive snapshot.
	policy4 := make(map[LPM4Key]PolicyValue)
	policy6 := make(map[LPM6Key]PolicyValue)
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
			policy4[key] = p.Value
			continue
		}
		key, err := PrefixToLPM6(p.Prefix)
		if err != nil {
			b.Publisher.AbortCompile()
			return err
		}
		policy6[key] = p.Value
	}
	b.Policy4[inactive] = policy4
	b.Policy6[inactive] = policy6
	gen, bank := b.Publisher.Commit()
	b.Control.ActiveBank = bank
	b.Control.PolicyGeneration = gen
	b.invalidateGenerationMaps(gen)
	b.Stats[25] = uint64(gen) // RELOAD_GENERATION index if aligned — best-effort
	return nil
}

// PublishFlow writes bidirectional flow verdicts.
func (b *MemoryBackend) PublishFlow(req FlowPublishRequest, nowNs uint64) error {
	ttl := DefaultFlowTTL(req.Protocol, req.TimeoutClass, req.TTL)
	expire := nowNs
	if ttlNs := uint64(ttl); ttlNs > ^uint64(0)-nowNs {
		expire = ^uint64(0)
	} else {
		expire += ttlNs
	}
	pair, err := BuildFlowPair(req, b.Control.PolicyGeneration, expire)
	if err != nil {
		return err
	}
	if b.Flows == nil {
		b.Flows = make(map[FlowKey]FlowValue)
	}
	if nowNs != 0 && (b.nextFlowPruneNs == 0 || nowNs >= b.nextFlowPruneNs) {
		b.pruneExpiredFlows(nowNs)
		b.nextFlowPruneNs = nowNs + flowPruneIntervalNs
	}
	limit := b.flowLimit
	if limit <= 0 {
		limit = maxMemoryFlowEntries
	}
	missing := 0
	if _, ok := b.Flows[pair.Forward]; !ok {
		missing++
	}
	if _, ok := b.Flows[pair.Reverse]; !ok {
		missing++
	}
	for len(b.Flows)+missing > limit {
		if !b.evictOldestFlowPair() {
			break
		}
	}
	b.Flows[pair.Forward] = pair.Value
	b.Flows[pair.Reverse] = pair.Value
	return nil
}

const (
	maxMemoryFlowEntries = DefaultFlowEntries
	flowPruneIntervalNs  = 30 * 1_000_000_000
)

func (b *MemoryBackend) pruneExpiredFlows(nowNs uint64) {
	for key, value := range b.Flows {
		if value.ExpiresNs != 0 && value.ExpiresNs <= nowNs {
			delete(b.Flows, key)
		}
	}
}

func (b *MemoryBackend) evictOldestFlowPair() bool {
	var oldestKey FlowKey
	var oldest uint64
	first := true
	for key, value := range b.Flows {
		if first || value.ExpiresNs < oldest {
			oldestKey, oldest = key, value.ExpiresNs
			first = false
		}
	}
	if first {
		return false
	}
	delete(b.Flows, oldestKey)
	reverse := oldestKey
	reverse.SPort, reverse.DPort = oldestKey.DPort, oldestKey.SPort
	reverse.SAddr, reverse.DAddr = oldestKey.DAddr, oldestKey.SAddr
	delete(b.Flows, reverse)
	return true
}

func (b *MemoryBackend) invalidateGenerationMaps(generation uint32) {
	if b == nil || generation == 0 {
		return
	}
	for key, value := range b.Flows {
		if value.Generation != generation {
			delete(b.Flows, key)
		}
	}
	if b.DNS != nil {
		b.DNS.InvalidateGeneration(generation)
	}
	b.nextFlowPruneNs = 0
}

// InvalidateGeneration drops exact-flow and DNS evidence from older policy
// epochs. The kernel maps use generation checks for correctness; the memory
// model also removes stale entries so those checks do not become a leak.
func (b *MemoryBackend) InvalidateGeneration(generation uint32) {
	if b == nil {
		return
	}
	b.invalidateGenerationMaps(generation)
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
	if !ok || v.Generation != b.Control.PolicyGeneration {
		return nil
	}
	return &v
}
