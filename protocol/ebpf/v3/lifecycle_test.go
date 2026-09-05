package v3

import (
	"net/netip"
	"testing"
	"time"

	ebpfv3 "github.com/sagernet/sing-box/common/ebpf/v3"
	"github.com/sagernet/sing-box/option"
)

func TestNormalizeEngineDefaultV2(t *testing.T) {
	o, err := NormalizeSharedNetwork(option.EBPFSharedNetworkOptions{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if o.Engine != EngineV2 {
		t.Fatalf("engine=%s", o.Engine)
	}
	if IsV3(o) {
		t.Fatal("not v3")
	}
}

func TestNormalizeV3RequiresSocketAssign(t *testing.T) {
	f := true
	_, err := NormalizeSharedNetwork(option.EBPFSharedNetworkOptions{
		Enabled:    true,
		Engine:     EngineV3,
		DataPlane:  "token",
		DropUDP443: &f,
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestLifecycleLearnAndStatic(t *testing.T) {
	drop := false
	lc, err := NewLifecycle(option.EBPFSharedNetworkOptions{
		Enabled:     true,
		Engine:      EngineV3,
		DataPlane:   "socket_assign",
		DropUDP443:  &drop,
		FailureMode: "proxy",
		PolicyOffload: option.EBPFPolicyOffloadOptions{
			Enabled:           true,
			StaticRules:       true,
			ExactFlowLearning: true,
			DNSIPHint:         "safe",
			FakeIP:            true,
		},
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer lc.Close()
	lc.ApplyControlFlags(true, true, true, true, true, 0x2b00)

	n, rej, err := lc.PublishStaticRules([]ebpfv3.CompileInput{{
		Destination: netip.MustParsePrefix("1.1.1.1/32"),
		Verdict:     ebpfv3.VerdictDirect,
		Kind:        ebpfv3.RuleKindStatic,
	}})
	if err != nil || n != 1 || rej != 0 {
		t.Fatalf("n=%d rej=%d err=%v", n, rej, err)
	}
	client := netip.MustParseAddrPort("10.0.0.2:1111")
	dest := netip.MustParseAddrPort("8.8.8.8:443")
	if err := lc.LearnFlow(client, dest, ebpfv3.ProtocolTCP, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	lc.ObserveDNS(netip.MustParseAddr("9.9.9.9"), true, ebpfv3.DNSEvidenceStrong, time.Minute, time.Now())
	lc.ObserveDNS(netip.MustParseAddr("9.9.9.9"), false, ebpfv3.DNSEvidenceStrong, time.Minute, time.Now())
	key := ebpfv3.DNSIPKey{Family: ebpfv3.AFInet, Addr: [16]byte{9, 9, 9, 9}}
	v, ok := lc.Backend().DNS.Lookup(key)
	if !ok || v.ProxyRefs == 0 || v.DirectRefs == 0 {
		t.Fatalf("conflict state %+v ok=%v", v, ok)
	}
	okDirect, _ := ebpfv3.DNSHintAllowsDirect(v, lc.Backend().Control.PolicyGeneration, uint64(time.Now().UnixNano()))
	if okDirect {
		t.Fatal("cdn conflict must not direct")
	}
}

type memSink struct {
	static  int
	flows   int
	dns     int
	merged  int
	invalid int
	deleted int
	mac     int
	gen     uint32

	controlWrites int
	flags         uint32
}

func (m *memSink) PublishStaticDirect(prefixes []netip.Prefix, generation uint32, bank uint32) error {
	m.static += len(prefixes)
	if generation == 0 {
		m.gen++
	} else {
		m.gen = generation
	}
	return nil
}
func (m *memSink) MergeStaticDirect(prefix netip.Prefix) error {
	if prefix.IsValid() {
		m.merged++
	}
	return nil
}
func (m *memSink) PutDirectFlow(protocol uint8, source, destination netip.AddrPort, ttl time.Duration) error {
	m.flows++
	return nil
}
func (m *memSink) DeleteDirectFlow(protocol uint8, source, destination netip.AddrPort) error {
	m.deleted++
	return nil
}
func (m *memSink) PublishMACPolicies(entries []ebpfv3.MACPolicyEntry) error {
	m.mac += len(entries)
	return nil
}
func (m *memSink) WriteControlV3(enabled bool, flags uint32, activeBank, generation, routingMark uint32) error {
	m.controlWrites++
	m.flags = flags
	return nil
}
func (m *memSink) PublishDNSHint(addr netip.Addr, direct bool, evidence uint8, generation uint32, ttl time.Duration) error {
	m.dns++
	return nil
}
func (m *memSink) InvalidateFlowDirect() error {
	m.invalid++
	m.gen++
	return nil
}
func (m *memSink) PolicyGeneration() uint32 { return m.gen }

func TestLifecycleBindSinkMirrorsKernel(t *testing.T) {
	drop := false
	lc, err := NewLifecycle(option.EBPFSharedNetworkOptions{
		Enabled: true, Engine: EngineV3, DataPlane: "socket_assign", DropUDP443: &drop,
		FailureMode: "proxy",
		PolicyOffload: option.EBPFPolicyOffloadOptions{
			Enabled: true, StaticRules: true, ExactFlowLearning: true, DNSIPHint: "safe", FakeIP: true,
		},
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer lc.Close()
	sink := &memSink{gen: 1}
	lc.BindSink(sink)
	_, _, err = lc.PublishStaticRules([]ebpfv3.CompileInput{{
		Destination: netip.MustParsePrefix("1.1.1.1/32"),
		Verdict:     ebpfv3.VerdictDirect,
		Kind:        ebpfv3.RuleKindStatic,
	}})
	if err != nil || sink.static != 1 {
		t.Fatalf("static sink=%d err=%v", sink.static, err)
	}
	client := netip.MustParseAddrPort("10.0.0.2:1111")
	dest := netip.MustParseAddrPort("8.8.8.8:443")
	if err := lc.LearnFlow(client, dest, ebpfv3.ProtocolTCP, true, time.Now()); err != nil || sink.flows != 1 {
		t.Fatalf("flow sink=%d err=%v", sink.flows, err)
	}
	lc.ObserveDNS(netip.MustParseAddr("9.9.9.9"), true, ebpfv3.DNSEvidenceStrong, time.Minute, time.Now())
	if sink.dns != 1 {
		t.Fatalf("dns sink=%d", sink.dns)
	}
	if err := lc.RevokeFlow(client, dest, ebpfv3.ProtocolTCP); err != nil || sink.deleted != 1 {
		t.Fatalf("revoke deleted=%d err=%v", sink.deleted, err)
	}
	if err := lc.InvalidateGeneration(); err != nil || sink.invalid != 1 {
		t.Fatalf("invalidate=%d err=%v", sink.invalid, err)
	}
}

func TestLifecyclePublishStaticRulesKeepsScopedDirectInUserspace(t *testing.T) {
	drop := false
	lc, err := NewLifecycle(option.EBPFSharedNetworkOptions{
		Enabled: true, Engine: EngineV3, DataPlane: "socket_assign", DropUDP443: &drop,
		PolicyOffload: option.EBPFPolicyOffloadOptions{Enabled: true, StaticRules: true},
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer lc.Close()
	sink := &memSink{gen: 1}
	lc.BindSink(sink)
	accepted, rejected, err := lc.PublishStaticRules([]ebpfv3.CompileInput{{
		Destination: netip.MustParsePrefix("203.0.113.0/24"),
		Protocol:    ebpfv3.ProtocolTCP,
		DPortMin:    443,
		DPortMax:    443,
		Verdict:     ebpfv3.VerdictDirect,
		Kind:        ebpfv3.RuleKindStatic,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if accepted != 0 || rejected != 1 {
		t.Fatalf("accepted=%d rejected=%d want 0/1", accepted, rejected)
	}
	if sink.static != 0 {
		t.Fatalf("scoped direct rule reached broad static sink: %d prefixes", sink.static)
	}
}

func TestLifecyclePublishStaticDirectMirrorsMemorySnapshot(t *testing.T) {
	drop := false
	lc, err := NewLifecycle(option.EBPFSharedNetworkOptions{
		Enabled: true, Engine: EngineV3, DataPlane: "socket_assign", DropUDP443: &drop,
		FailureMode:   "proxy",
		PolicyOffload: option.EBPFPolicyOffloadOptions{Enabled: true, StaticRules: true},
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer lc.Close()
	sink := &memSink{gen: 1}
	lc.BindSink(sink)
	prefix := netip.MustParsePrefix("203.0.113.7/32")
	if err := lc.PublishStaticDirect([]netip.Prefix{prefix, prefix}); err != nil {
		t.Fatal(err)
	}
	if sink.static != 1 {
		t.Fatalf("kernel snapshot received %d prefixes", sink.static)
	}
	if got := lc.Backend().LookupStatic(prefix.Addr(), ebpfv3.ProtocolTCP, 443); got == nil {
		t.Fatal("memory snapshot did not receive direct prefix")
	} else if got.Verdict != uint8(ebpfv3.VerdictDirect) || got.Source != uint8(ebpfv3.SourceStatic) {
		t.Fatalf("unexpected memory policy: %+v", *got)
	}
	if lc.Backend().Control.PolicyGeneration != sink.gen {
		t.Fatalf("generation diverged: memory=%d kernel=%d", lc.Backend().Control.PolicyGeneration, sink.gen)
	}
}

func TestLifecycleGenerationSyncKeepsPublisherMonotonic(t *testing.T) {
	drop := false
	lc, err := NewLifecycle(option.EBPFSharedNetworkOptions{
		Enabled: true, Engine: EngineV3, DataPlane: "socket_assign", DropUDP443: &drop,
		PolicyOffload: option.EBPFPolicyOffloadOptions{Enabled: true, StaticRules: true},
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer lc.Close()
	lc.SyncPolicyGeneration(10)
	lc.SyncPolicyGeneration(12)
	if got := lc.Backend().Publisher.Generation(); got != 12 {
		t.Fatalf("publisher generation=%d want 12", got)
	}
	if err := lc.Backend().PublishStatic(nil); err != nil {
		t.Fatal(err)
	}
	if got := lc.Backend().Control.PolicyGeneration; got != 13 {
		t.Fatalf("control generation=%d want 13", got)
	}
}

func TestLifecycleMergeStaticDirectMirrorsSinkAndModel(t *testing.T) {
	drop := false
	lc, err := NewLifecycle(option.EBPFSharedNetworkOptions{
		Enabled: true, Engine: EngineV3, DataPlane: "socket_assign", DropUDP443: &drop,
		PolicyOffload: option.EBPFPolicyOffloadOptions{Enabled: true, StaticRules: true},
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer lc.Close()
	sink := &memSink{gen: 1}
	lc.BindSink(sink)
	prefix := netip.MustParsePrefix("203.0.113.10/32")
	if err := lc.MergeStaticDirect(prefix); err != nil {
		t.Fatal(err)
	}
	if sink.merged != 1 {
		t.Fatalf("sink merges=%d", sink.merged)
	}
	if got := lc.Backend().LookupStatic(prefix.Addr(), ebpfv3.ProtocolTCP, 443); got == nil {
		t.Fatal("memory model did not receive merged policy")
	}
}

func TestControlFlagsNoDefaultQUICDrop(t *testing.T) {
	f := false
	flags := ControlFlags(option.EBPFSharedNetworkOptions{
		DataPlane:     "socket_assign",
		DropUDP443:    &f,
		PolicyOffload: option.EBPFPolicyOffloadOptions{Enabled: true, StaticRules: true},
	}, true, true, true, true, true, 0)
	if flags&ebpfv3.FlagDropUDP443 != 0 {
		t.Fatal("quic drop must be off")
	}
	if flags&ebpfv3.FlagStaticPolicy == 0 || flags&ebpfv3.FlagSocketAssign == 0 {
		t.Fatalf("flags=%x", flags)
	}
}

func TestLifecyclePublishMACSourcePolicies(t *testing.T) {
	drop := false
	newLifecycle := func(macSource bool) *Lifecycle {
		t.Helper()
		lc, err := NewLifecycle(option.EBPFSharedNetworkOptions{
			Enabled:    true,
			Engine:     EngineV3,
			DataPlane:  "socket_assign",
			DropUDP443: &drop,
			PolicyOffload: option.EBPFPolicyOffloadOptions{
				Enabled:         true,
				MACSourcePolicy: macSource,
			},
		}, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		return lc
	}
	entries := []ebpfv3.MACPolicyEntry{{
		Key:   ebpfv3.MACKey{Addr: [6]byte{0xaa, 0xbb, 0xcc, 0x01, 0x02, 0x03}},
		Value: ebpfv3.MACPolicyValue{Verdict: uint8(ebpfv3.VerdictDirect), Confidence: ebpfv3.ConfidenceAuthoritative},
	}}

	// Disabled policy is a no-op in both representations.
	lc := newLifecycle(false)
	defer lc.Close()
	sink := &memSink{}
	lc.BindSink(sink)
	if err := lc.PublishMACSourcePolicies(entries); err != nil {
		t.Fatal(err)
	}
	if sink.mac != 0 || len(lc.backend.MACPolicies) != 0 {
		t.Fatalf("disabled mac policy published: sink=%d model=%d", sink.mac, len(lc.backend.MACPolicies))
	}

	// Enabled policy mirrors to sink and model with generation tagging.
	lc2 := newLifecycle(true)
	defer lc2.Close()
	sink2 := &memSink{}
	lc2.BindSink(sink2)
	if err := lc2.PublishMACSourcePolicies(entries); err != nil {
		t.Fatal(err)
	}
	if sink2.mac != 1 {
		t.Fatalf("sink entries=%d", sink2.mac)
	}
	if len(lc2.backend.MACPolicies) != 1 {
		t.Fatalf("model entries=%d", len(lc2.backend.MACPolicies))
	}
	for _, value := range lc2.backend.MACPolicies {
		if value.Generation == 0 {
			t.Fatal("mac row not generation-tagged")
		}
		if value.Source != uint8(ebpfv3.SourceStatic) {
			t.Fatalf("unexpected source %d", value.Source)
		}
	}

	// An empty snapshot retires all rows (authoritative replace).
	if err := lc2.PublishMACSourcePolicies(nil); err != nil {
		t.Fatal(err)
	}
	if len(lc2.backend.MACPolicies) != 0 {
		t.Fatalf("stale mac rows survived snapshot replace: %d", len(lc2.backend.MACPolicies))
	}
}
