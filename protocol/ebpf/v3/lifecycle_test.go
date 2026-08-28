package v3

import (
	"errors"
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
	gen     uint32
}

type rejectingStaticSink struct{ memSink }

type rejectingInvalidateSink struct{ memSink }

type rejectingFlowSink struct{ memSink }

type rejectingDNSSink struct{ memSink }

func (s *rejectingStaticSink) PublishStaticDirect(prefixes []netip.Prefix, generation uint32, bank uint32) error {
	return errors.New("injected static publish failure")
}

func (s *rejectingInvalidateSink) InvalidateFlowDirect() error {
	return errors.New("injected invalidate failure")
}

func (s *rejectingFlowSink) PutDirectFlow(protocol uint8, source, destination netip.AddrPort, ttl time.Duration) error {
	return errors.New("injected flow publish failure")
}

func (s *rejectingDNSSink) PublishDNSHint(addr netip.Addr, direct bool, evidence uint8, generation uint32, ttl time.Duration) error {
	return errors.New("injected DNS hint publish failure")
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

func TestLifecycleStaticSinkFailureDoesNotAdvanceMirror(t *testing.T) {
	drop := false
	lc, err := NewLifecycle(option.EBPFSharedNetworkOptions{
		Enabled: true, Engine: EngineV3, DataPlane: "socket_assign", DropUDP443: &drop,
		PolicyOffload: option.EBPFPolicyOffloadOptions{Enabled: true, StaticRules: true},
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer lc.Close()
	sink := &rejectingStaticSink{memSink: memSink{gen: 1}}
	lc.BindSink(sink)
	before := lc.Backend().Control
	if _, _, err := lc.PublishStaticRules([]ebpfv3.CompileInput{{
		Destination: netip.MustParsePrefix("1.1.1.1/32"),
		Verdict:     ebpfv3.VerdictDirect, Kind: ebpfv3.RuleKindStatic,
	}}); err == nil {
		t.Fatal("expected sink failure")
	}
	after := lc.Backend().Control
	if after != before {
		t.Fatalf("mirror advanced after sink failure: before=%+v after=%+v", before, after)
	}
}

func TestLifecycleFlowSinkFailureRollsBackMirror(t *testing.T) {
	drop := false
	lc, err := NewLifecycle(option.EBPFSharedNetworkOptions{
		Enabled: true, Engine: EngineV3, DataPlane: "socket_assign", DropUDP443: &drop,
		PolicyOffload: option.EBPFPolicyOffloadOptions{Enabled: true, ExactFlowLearning: true},
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer lc.Close()
	lc.BindSink(&rejectingFlowSink{memSink: memSink{gen: 1}})
	client := netip.MustParseAddrPort("10.0.0.2:1111")
	dest := netip.MustParseAddrPort("8.8.8.8:443")
	if err := lc.LearnFlow(client, dest, ebpfv3.ProtocolTCP, true, time.Now()); err == nil {
		t.Fatal("expected flow sink failure")
	}
	if flow := lc.Backend().LookupFlow(ebpfv3.FlowKey{}); flow != nil {
		t.Fatal("failed live flow publish left a mirror entry")
	}
	if len(lc.Backend().Flows) != 0 {
		t.Fatalf("failed live flow publish left %d mirror entries", len(lc.Backend().Flows))
	}
}

func TestLifecycleDNSSinkFailureDoesNotAdvanceMirror(t *testing.T) {
	drop := false
	lc, err := NewLifecycle(option.EBPFSharedNetworkOptions{
		Enabled: true, Engine: EngineV3, DataPlane: "socket_assign", DropUDP443: &drop,
		PolicyOffload: option.EBPFPolicyOffloadOptions{Enabled: true, DNSIPHint: "safe"},
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer lc.Close()
	lc.BindSink(&rejectingDNSSink{memSink: memSink{gen: 1}})
	addr := netip.MustParseAddr("9.9.9.9")
	lc.ObserveDNS(addr, true, ebpfv3.DNSEvidenceStrong, time.Minute, time.Now())
	key := ebpfv3.DNSIPKey{Family: ebpfv3.AFInet, Addr: [16]byte{9, 9, 9, 9}}
	if _, ok := lc.Backend().DNS.Lookup(key); ok {
		t.Fatal("failed live DNS publish left a mirror hint")
	}
}

func TestLifecycleGenerationSyncAndInvalidationStayAligned(t *testing.T) {
	drop := false
	lc, err := NewLifecycle(option.EBPFSharedNetworkOptions{
		Enabled: true, Engine: EngineV3, DataPlane: "socket_assign", DropUDP443: &drop,
		PolicyOffload: option.EBPFPolicyOffloadOptions{Enabled: true, StaticRules: true},
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer lc.Close()
	if _, _, err := lc.PublishStaticRules([]ebpfv3.CompileInput{{
		Destination: netip.MustParsePrefix("1.1.1.1/32"),
		Verdict:     ebpfv3.VerdictDirect,
		Kind:        ebpfv3.RuleKindStatic,
	}}); err != nil {
		t.Fatal(err)
	}
	committed := lc.Backend().Control.PolicyGeneration
	if committed != lc.Backend().Publisher.Generation() {
		t.Fatalf("initial generations diverged: control=%d publisher=%d", committed, lc.Backend().Publisher.Generation())
	}
	// A late reload callback must not regress the accepted generation.
	lc.SyncPolicyGeneration(committed - 1)
	if got := lc.Backend().Control.PolicyGeneration; got != committed {
		t.Fatalf("stale sync regressed control generation to %d", got)
	}
	if err := lc.InvalidateGeneration(); err != nil {
		t.Fatal(err)
	}
	invalidated := lc.Backend().Control.PolicyGeneration
	if invalidated != committed+1 || invalidated != lc.Backend().Publisher.Generation() {
		t.Fatalf("invalidation generations diverged: control=%d publisher=%d", invalidated, lc.Backend().Publisher.Generation())
	}
}

func TestLifecycleInvalidationFailureDoesNotAdvanceMirror(t *testing.T) {
	drop := false
	lc, err := NewLifecycle(option.EBPFSharedNetworkOptions{
		Enabled: true, Engine: EngineV3, DataPlane: "socket_assign", DropUDP443: &drop,
		PolicyOffload: option.EBPFPolicyOffloadOptions{Enabled: true},
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer lc.Close()
	sink := &rejectingInvalidateSink{memSink: memSink{gen: 1}}
	lc.BindSink(sink)
	before := lc.Backend().Control
	if err := lc.InvalidateGeneration(); err == nil {
		t.Fatal("expected invalidate failure")
	}
	after := lc.Backend().Control
	if after != before || lc.Backend().Publisher.Generation() != before.PolicyGeneration {
		t.Fatalf("mirror advanced after invalidate failure: before=%+v after=%+v publisher=%d", before, after, lc.Backend().Publisher.Generation())
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
