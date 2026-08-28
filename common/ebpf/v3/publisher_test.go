package v3

import (
	"net/netip"
	"testing"
	"time"
)

func TestPublishStaticAtomicAndGeneration(t *testing.T) {
	b := NewMemoryBackend()
	prefix := netip.MustParsePrefix("1.1.1.1/32")
	compiled, rejected, err := CompileStatic([]CompileInput{{
		Destination: prefix,
		Verdict:     VerdictDirect,
		Kind:        RuleKindStatic,
		PolicyID:    7,
	}}, 1)
	if err != nil || len(rejected) != 0 || len(compiled) != 1 {
		t.Fatalf("compile err=%v rejected=%d compiled=%d", err, len(rejected), len(compiled))
	}
	if err := b.PublishStatic(compiled); err != nil {
		t.Fatal(err)
	}
	if b.Control.PolicyGeneration != 2 || b.Control.ActiveBank != 1 {
		t.Fatalf("control %+v", b.Control)
	}
	v := b.LookupStatic(netip.MustParseAddr("1.1.1.1"), ProtocolTCP, 443)
	if v == nil || v.Verdict != uint8(VerdictDirect) || v.Generation != 2 {
		t.Fatalf("lookup %+v", v)
	}
	// Second publish flips bank again; old bank entries not consulted.
	if err := b.PublishStatic(compiled); err != nil {
		t.Fatal(err)
	}
	if b.Control.PolicyGeneration != 3 || b.Control.ActiveBank != 0 {
		t.Fatalf("second %+v", b.Control)
	}
}

func TestCompileRejectsDomainAndGroup(t *testing.T) {
	_, rejected, err := CompileStatic([]CompileInput{
		{Destination: netip.MustParsePrefix("1.1.1.1/32"), Verdict: VerdictDirect, DomainBound: true},
		{Destination: netip.MustParsePrefix("2.2.2.2/32"), Verdict: VerdictDirect, LeafIsGroup: true},
		{Destination: netip.MustParsePrefix("3.3.3.3/32"), Verdict: VerdictDirect, UsesSniff: true},
	}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(rejected) != 3 {
		t.Fatalf("rejected=%d", len(rejected))
	}
}

func TestFlowLearnBareDirectOnly(t *testing.T) {
	b := NewMemoryBackend()
	client := netip.MustParseAddrPort("10.0.0.2:12345")
	dest := netip.MustParseAddrPort("8.8.8.8:443")
	err := b.PublishFlow(FlowPublishRequest{
		Client: client, Destination: dest, Protocol: ProtocolTCP,
		Verdict: VerdictDirect, LeafIsBareDirect: false,
	}, 100)
	if err == nil {
		t.Fatal("expected reject non-bare direct")
	}
	if err := b.PublishFlow(FlowPublishRequest{
		Client: client, Destination: dest, Protocol: ProtocolTCP,
		Verdict: VerdictDirect, LeafIsBareDirect: true,
	}, 100); err != nil {
		t.Fatal(err)
	}
	// generation miss after reload
	_ = b.PublishStatic(nil)
	key := FlowKey{
		Family: AFInet, Protocol: ProtocolTCP, Direction: 0,
		SPort: 12345, DPort: 443,
		SAddr: [16]byte{10, 0, 0, 2}, DAddr: [16]byte{8, 8, 8, 8},
	}
	if b.LookupFlow(key) != nil {
		t.Fatal("old generation flow must miss after policy commit")
	}
}

func TestFlowRevokeOnFailure(t *testing.T) {
	b := NewMemoryBackend()
	client := netip.MustParseAddrPort("10.0.0.2:12345")
	dest := netip.MustParseAddrPort("8.8.8.8:443")
	if err := b.PublishFlow(FlowPublishRequest{
		Client: client, Destination: dest, Protocol: ProtocolTCP,
		Verdict: VerdictDirect, LeafIsBareDirect: true,
	}, 100); err != nil {
		t.Fatal(err)
	}
	if err := b.RevokeFlow(client, dest, ProtocolTCP); err != nil {
		t.Fatal(err)
	}
	key := FlowKey{
		Family: AFInet, Protocol: ProtocolTCP, Direction: 0,
		SPort: 12345, DPort: 443,
		SAddr: [16]byte{10, 0, 0, 2}, DAddr: [16]byte{8, 8, 8, 8},
	}
	if b.LookupFlow(key) != nil {
		t.Fatal("revoked")
	}
}

func TestIPv4IPv6FlowSymmetric(t *testing.T) {
	b := NewMemoryBackend()
	c4 := netip.MustParseAddrPort("10.0.0.2:1000")
	d4 := netip.MustParseAddrPort("1.1.1.1:443")
	c6 := netip.MustParseAddrPort("[fd00::2]:1000")
	d6 := netip.MustParseAddrPort("[2001:db8::1]:443")
	for _, req := range []FlowPublishRequest{
		{Client: c4, Destination: d4, Protocol: ProtocolUDP, Verdict: VerdictDirect, LeafIsBareDirect: true, TimeoutClass: "quic"},
		{Client: c6, Destination: d6, Protocol: ProtocolUDP, Verdict: VerdictDirect, LeafIsBareDirect: true, TimeoutClass: "quic"},
	} {
		if err := b.PublishFlow(req, 1); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFlowMirrorExpiresAndStaysBounded(t *testing.T) {
	b := NewMemoryBackend()
	now := uint64(time.Now().UnixNano())
	// Seed a full mirror to model a long-lived gateway before the next learn.
	for i := 0; i < DefaultFlowEntries; i++ {
		key := FlowKey{Family: AFInet, Protocol: ProtocolTCP, SPort: uint16(i), DPort: 443, SAddr: [16]byte{10, 0, byte(i >> 8), byte(i)}}
		b.Flows[key] = FlowValue{Generation: b.Control.PolicyGeneration, ExpiresNs: now + uint64(time.Hour)}
	}
	if err := b.PublishFlow(FlowPublishRequest{
		Client: netip.MustParseAddrPort("10.10.0.2:12345"), Destination: netip.MustParseAddrPort("8.8.8.8:443"),
		Protocol: ProtocolTCP, Verdict: VerdictDirect, LeafIsBareDirect: true,
	}, now); err != nil {
		t.Fatal(err)
	}
	if len(b.Flows) > DefaultFlowEntries {
		t.Fatalf("flow mirror exceeded bound: %d", len(b.Flows))
	}
	key := FlowKey{Family: AFInet, Protocol: ProtocolTCP, SPort: 12345, DPort: 443, SAddr: [16]byte{10, 10, 0, 2}, DAddr: [16]byte{8, 8, 8, 8}}
	b.Flows[key] = FlowValue{Generation: b.Control.PolicyGeneration, ExpiresNs: now - 1}
	if b.LookupFlow(key) != nil {
		t.Fatal("expired flow mirror entry was returned")
	}
}

func TestPublishStaticRejectsOverCapacityWithoutCommit(t *testing.T) {
	b := NewMemoryBackend()
	policies := make([]CompiledPolicy, MaxPolicyLPM+1)
	for i := range policies {
		policies[i] = CompiledPolicy{
			Prefix: netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1}), 32),
			Value:  PolicyValue{Verdict: uint8(VerdictDirect)},
		}
	}
	previousGeneration := b.Control.PolicyGeneration
	previousBank := b.Control.ActiveBank
	if err := b.PublishStatic(policies); err == nil {
		t.Fatal("over-capacity static policy update unexpectedly committed")
	}
	if b.Control.PolicyGeneration != previousGeneration || b.Control.ActiveBank != previousBank {
		t.Fatalf("failed static update changed active control: %+v", b.Control)
	}
}

func TestPublishStaticGenerationWrapMatchesPublisher(t *testing.T) {
	b := NewMemoryBackend()
	b.Publisher.generation.Store(^uint32(0))
	b.Control.PolicyGeneration = ^uint32(0)
	compiled, rejected, err := CompileStatic([]CompileInput{{
		Destination: netip.MustParsePrefix("192.0.2.1/32"),
		Verdict:     VerdictDirect,
		Kind:        RuleKindStatic,
	}}, ^uint32(0))
	if err != nil || len(rejected) != 0 || len(compiled) != 1 {
		t.Fatalf("compile err=%v rejected=%d compiled=%d", err, len(rejected), len(compiled))
	}
	if err := b.PublishStatic(compiled); err != nil {
		t.Fatal(err)
	}
	if b.Publisher.Generation() != 1 || b.Control.PolicyGeneration != 1 {
		t.Fatalf("wrapped generation publisher=%d control=%d", b.Publisher.Generation(), b.Control.PolicyGeneration)
	}
	v := b.LookupStatic(netip.MustParseAddr("192.0.2.1"), ProtocolTCP, 443)
	if v == nil || v.Generation != 1 {
		t.Fatalf("wrapped policy generation=%+v", v)
	}
}
