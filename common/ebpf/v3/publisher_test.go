package v3

import (
	"net/netip"
	"testing"
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
