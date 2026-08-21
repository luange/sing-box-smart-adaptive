package group

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/nodefilter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
)

type smartFakeOutbound struct {
	outbound.Adapter
	dialError error
	dialDelay time.Duration
	dials     atomic.Int64
	peers     chan net.Conn
}

type smartFakeGroup struct {
	*smartFakeOutbound
	children []string
}

func (g *smartFakeGroup) Now() string {
	if len(g.children) == 0 {
		return ""
	}
	return g.children[0]
}

func (g *smartFakeGroup) All() []string {
	return append([]string(nil), g.children...)
}

type smartFakeOutboundManager struct {
	adapter.OutboundManager
	byTag map[string]adapter.Outbound
}

type smartFakeProvider struct {
	adapter.Provider
	tag       string
	outbounds []adapter.Outbound
	callbacks list.List[adapter.ProviderUpdateCallback]
}

func (p *smartFakeProvider) Tag() string { return p.tag }

func (p *smartFakeProvider) Outbounds() []adapter.Outbound {
	return append([]adapter.Outbound(nil), p.outbounds...)
}

func (p *smartFakeProvider) RegisterCallback(callback adapter.ProviderUpdateCallback) *list.Element[adapter.ProviderUpdateCallback] {
	return p.callbacks.PushBack(callback)
}

func (p *smartFakeProvider) UnregisterCallback(element *list.Element[adapter.ProviderUpdateCallback]) {
	p.callbacks.Remove(element)
}

func (p *smartFakeProvider) update(outbounds ...adapter.Outbound) error {
	p.outbounds = append([]adapter.Outbound(nil), outbounds...)
	for element := p.callbacks.Front(); element != nil; element = element.Next() {
		if err := element.Value(p.tag); err != nil {
			return err
		}
	}
	return nil
}

func (p *smartFakeProvider) callbackCount() int {
	return p.callbacks.Len()
}

type smartFakeProviderManager struct {
	adapter.ProviderManager
	provider adapter.Provider
}

func (m *smartFakeProviderManager) Providers() []adapter.Provider {
	return []adapter.Provider{m.provider}
}

func (m *smartFakeProviderManager) Get(tag string) (adapter.Provider, bool) {
	if m.provider != nil && m.provider.Tag() == tag {
		return m.provider, true
	}
	return nil, false
}

func (m *smartFakeOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	candidate, loaded := m.byTag[tag]
	return candidate, loaded
}

func newSmartFakeOutbound(tag string, dialError error) *smartFakeOutbound {
	return newSmartFakeOutboundNetworks(tag, []string{N.NetworkTCP}, dialError)
}

func newSmartFakeOutboundNetworks(tag string, networks []string, dialError error) *smartFakeOutbound {
	return &smartFakeOutbound{
		Adapter:   outbound.NewAdapter(C.TypeDirect, tag, networks, nil),
		dialError: dialError,
		peers:     make(chan net.Conn, 8),
	}
}

func (f *smartFakeOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	f.dials.Add(1)
	if f.dialDelay > 0 {
		timer := time.NewTimer(f.dialDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	if f.dialError != nil {
		return nil, f.dialError
	}
	local, peer := net.Pipe()
	f.peers <- peer
	return local, nil
}

func (f *smartFakeOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}

func newTestSmart(candidates ...adapter.Outbound) *Smart {
	candidateByTag := make(map[string]adapter.Outbound, len(candidates))
	for _, candidate := range candidates {
		candidateByTag[candidate.Tag()] = candidate
	}
	return &Smart{
		Adapter:           outbound.NewAdapter(C.TypeSmart, "smart-test", []string{N.NetworkTCP, N.NetworkUDP}, nil),
		ctx:               context.Background(),
		candidates:        candidates,
		candidateByTag:    candidateByTag,
		control:           &smartControlState{},
		lastSelected:      make(map[string]string),
		affinity:          make(map[string]smartAffinity),
		switchChallenges:  make(map[string]smartSwitchChallenge),
		halfOpen:          make(map[string]struct{}),
		store:             newSmartStore(time.Hour, 1, time.Minute),
		maxAttempts:       3,
		attemptTimeout:    time.Second,
		probeTimeout:      100 * time.Millisecond,
		siteStickiness:    time.Minute,
		switchConfirm:     30 * time.Second,
		switchMargin:      0.10,
		exploration:       0,
		minSamples:        3,
		maxHistoryEntries: 50000,
		interruptGroup:    interruptGroupForTest(),
	}
}

func interruptGroupForTest() *interrupt.Group {
	return interrupt.NewGroup()
}

func TestSmartDialFailsOverWithinSameRequest(t *testing.T) {
	first := newSmartFakeOutbound("first", errors.New("dial failed"))
	second := newSmartFakeOutbound("second", nil)
	smart := newTestSmart(first, second)

	conn, err := smart.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("example.com:443"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	peer := <-second.peers
	defer peer.Close()
	if first.dials.Load() != 1 || second.dials.Load() != 1 {
		t.Fatalf("unexpected dial counts: first=%d second=%d", first.dials.Load(), second.dials.Load())
	}
	if smart.Now() != "second" {
		t.Fatalf("expected second selected, got %q", smart.Now())
	}
}

func TestSmartDialHedgesSlowCandidateWithinSameRequest(t *testing.T) {
	first := newSmartFakeOutbound("first", nil)
	first.dialDelay = 400 * time.Millisecond
	second := newSmartFakeOutbound("second", nil)
	smart := newTestSmart(first, second)
	smart.attemptTimeout = 900 * time.Millisecond

	startedAt := time.Now()
	conn, err := smart.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("example.com:443"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if elapsed := time.Since(startedAt); elapsed >= first.dialDelay {
		t.Fatalf("Smart waited for slow candidate instead of hedging: elapsed=%s", elapsed)
	}
	peer := <-second.peers
	defer peer.Close()
	if first.dials.Load() != 1 || second.dials.Load() != 1 {
		t.Fatalf("unexpected dial counts: first=%d second=%d", first.dials.Load(), second.dials.Load())
	}
	if smart.Now() != "second" {
		t.Fatalf("expected hedged candidate selected, got %q", smart.Now())
	}
}

func TestSmartWaitsForProviderStartup(t *testing.T) {
	provider := &smartFakeProvider{tag: "airport"}
	smart := newTestSmart()
	smart.provider = &smartFakeProviderManager{provider: provider}
	smart.outbound = &smartFakeOutboundManager{byTag: make(map[string]adapter.Outbound)}
	smart.providers = make(map[string]adapter.Provider)
	smart.outboundsCache = make(map[string][]adapter.Outbound)
	smart.providerTags = []string{"airport"}

	if err := smart.Start(); err != nil {
		t.Fatalf("smart rejected provider warming state: %v", err)
	}
	if status := smart.SmartStatus(); status.Reason != "warming: waiting for provider candidates" {
		t.Fatalf("unexpected warming status: %q", status.Reason)
	}

	candidate := newSmartFakeOutbound("airport/hk", nil)
	if err := provider.update(candidate); err != nil {
		t.Fatalf("provider update failed: %v", err)
	}
	if all := smart.All(); len(all) != 1 || all[0] != candidate.Tag() {
		t.Fatalf("provider candidates were not installed: %v", all)
	}
	status := smart.SmartStatus()
	if status.CandidateCount != 1 || status.Reason != "warming: candidates loaded, awaiting observations" {
		t.Fatalf("provider readiness status was not published: %+v", status)
	}
}

func TestSmartCloseUnregistersProviderCallback(t *testing.T) {
	candidate := newSmartFakeOutbound("airport/hk", nil)
	provider := &smartFakeProvider{tag: "airport", outbounds: []adapter.Outbound{candidate}}
	smart := newTestSmart()
	smart.provider = &smartFakeProviderManager{provider: provider}
	smart.outbound = &smartFakeOutboundManager{byTag: make(map[string]adapter.Outbound)}
	smart.providers = make(map[string]adapter.Provider)
	smart.outboundsCache = make(map[string][]adapter.Outbound)
	smart.providerTags = []string{"airport"}
	if err := smart.Start(); err != nil {
		t.Fatal(err)
	}
	if provider.callbackCount() != 1 {
		t.Fatalf("expected one provider callback, got %d", provider.callbackCount())
	}
	if err := smart.Close(); err != nil {
		t.Fatal(err)
	}
	if provider.callbackCount() != 0 {
		t.Fatalf("retired Smart callback remained registered: %d", provider.callbackCount())
	}
	if err := provider.update(candidate); err != nil {
		t.Fatalf("provider update after Smart close failed: %v", err)
	}
}

func TestSmartProviderRefreshClearsRemovedLatestCandidate(t *testing.T) {
	first := newSmartFakeOutbound("airport/old", nil)
	provider := &smartFakeProvider{tag: "airport", outbounds: []adapter.Outbound{first}}
	smart := newTestSmart()
	smart.provider = &smartFakeProviderManager{provider: provider}
	smart.outbound = &smartFakeOutboundManager{byTag: make(map[string]adapter.Outbound)}
	smart.providers = make(map[string]adapter.Provider)
	smart.outboundsCache = make(map[string][]adapter.Outbound)
	smart.providerTags = []string{"airport"}
	if err := smart.Start(); err != nil {
		t.Fatal(err)
	}
	defer smart.Close()
	smart.latest.Store(first)
	if smart.Now() != first.Tag() {
		t.Fatal("latest candidate was not visible before provider refresh")
	}
	second := newSmartFakeOutbound("airport/new", nil)
	if err := provider.update(second); err != nil {
		t.Fatal(err)
	}
	if smart.Now() != "" {
		t.Fatalf("removed provider candidate remained selected: %q", smart.Now())
	}
}

type smartBlockingPacketOutbound struct {
	outbound.Adapter
}

func newSmartBlockingPacketOutbound(tag string) *smartBlockingPacketOutbound {
	return &smartBlockingPacketOutbound{
		Adapter: outbound.NewAdapter(C.TypeDirect, tag, []string{N.NetworkUDP}, nil),
	}
}

func (o *smartBlockingPacketOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, net.ErrClosed
}

func (o *smartBlockingPacketOutbound) ListenPacket(ctx context.Context, _ M.Socksaddr) (net.PacketConn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestSmartUDPAttemptUsesAttemptTimeout(t *testing.T) {
	candidate := newSmartBlockingPacketOutbound("slow-udp")
	smart := newTestSmart(candidate)
	smart.maxAttempts = 1
	smart.attemptTimeout = 25 * time.Millisecond
	startedAt := time.Now()
	_, err := smart.ListenPacket(context.Background(), M.ParseSocksaddr("1.1.1.1:53"))
	if err == nil {
		t.Fatal("expected UDP attempt timeout")
	}
	if elapsed := time.Since(startedAt); elapsed > 250*time.Millisecond {
		t.Fatalf("UDP attempt ignored attempt_timeout: %v", elapsed)
	}
}

type smartCanceledProbeOutbound struct {
	outbound.Adapter
}

func newSmartCanceledProbeOutbound(tag string) *smartCanceledProbeOutbound {
	return &smartCanceledProbeOutbound{Adapter: outbound.NewAdapter(C.TypeDirect, tag, []string{N.NetworkTCP}, nil)}
}

func (o *smartCanceledProbeOutbound) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (*smartCanceledProbeOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

func TestSmartProbeCancellationDoesNotDeadlockDispatcher(t *testing.T) {
	candidates := make([]adapter.Outbound, 64)
	for index := range candidates {
		candidates[index] = newSmartCanceledProbeOutbound("probe-" + strconv.Itoa(index))
	}
	smart := newTestSmart(candidates...)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		_, _ = smart.probe(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("canceled Smart probe deadlocked while dispatching candidates")
	}
}

func TestSmartProbeDeadlineCommitsCompletedObservations(t *testing.T) {
	fast := newSmartFakeOutbound("probe-fast", nil)
	slow := newSmartFakeOutbound("probe-slow", nil)
	smart := newTestSmart(fast, slow)
	registry := newSmartProbeRegistry(context.Background())
	defer registry.close()
	registry.probe = func(ctx context.Context, _ string, candidate adapter.Outbound) (uint16, error) {
		if candidate.Tag() == fast.Tag() {
			return 12, nil
		}
		<-ctx.Done()
		return 0, ctx.Err()
	}
	smart.probeRegistry = registry
	smart.candidateProbeKey = map[string]string{
		fast.Tag(): fast.Tag(),
		slow.Tag(): slow.Tag(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	result, err := smart.probe(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected partial-cycle deadline, got %v", err)
	}
	if result[fast.Tag()] != 12 {
		t.Fatalf("completed probe missing from result: %v", result)
	}
	estimate := smart.store.estimate(time.Now(), smart.networkFingerprint(), "", fast.Tag(), N.NetworkTCP, smart.minSamples)
	if estimate.State == "unknown" || estimate.Samples == 0 {
		t.Fatalf("completed observation was discarded at deadline: %+v", estimate)
	}
	status := smart.SmartStatus()
	if len(status.Candidates) == 0 || status.Candidates[0].Samples == 0 {
		t.Fatalf("completed observation was not published without traffic: %+v", status)
	}
}

func TestSmartRequestProbeCoalesces(t *testing.T) {
	smart := &Smart{probeNow: make(chan struct{}, 1)}
	smart.requestProbe()
	smart.requestProbe()
	if got := len(smart.probeNow); got != 1 {
		t.Fatalf("queued probes=%d, want 1", got)
	}
}

func TestSmartBasicProbeRequiresConfirmedFailure(t *testing.T) {
	candidate := newSmartFakeOutbound("bootstrap-candidate", nil)
	smart := newTestSmart(candidate)
	registry := newSmartProbeRegistry(context.Background())
	defer registry.close()
	smart.probeRegistry = registry
	smart.candidateProbeKey = map[string]string{candidate.Tag(): candidate.Tag()}
	key := smartProbeKey(candidate.Tag(), smart.probeURL, smart.probeTimeout)
	registry.entries[key] = &smartProbeEntry{result: smartProbeResult{
		success: false, failures: 1, nextProbeAt: time.Now().Add(time.Minute),
	}}
	ranks, _, _, _ := smart.rank(context.Background(), N.NetworkTCP, M.Socksaddr{})
	if len(ranks) != 1 || ranks[0].status.State == "open" {
		t.Fatalf("one basic-probe failure must not remove the cold-start candidate: %+v", ranks)
	}
	registry.entries[key].result.failures = 3
	ranks, _, _, _ = smart.rank(context.Background(), N.NetworkTCP, M.Socksaddr{})
	if len(ranks) != 1 || ranks[0].status.State != "open" {
		t.Fatalf("three consecutive basic-probe failures must isolate the candidate: %+v", ranks)
	}
}

func TestSmartProbePublishesFirstSuccessBeforeCycleCompletes(t *testing.T) {
	fast := newSmartFakeOutbound("stream-fast", nil)
	slow := newSmartFakeOutbound("stream-slow", nil)
	smart := newTestSmart(fast, slow)
	registry := newSmartProbeRegistry(context.Background())
	defer registry.close()
	releaseSlow := make(chan struct{})
	registry.probe = func(_ context.Context, _ string, candidate adapter.Outbound) (uint16, error) {
		if candidate.Tag() == fast.Tag() {
			return 9, nil
		}
		<-releaseSlow
		return 10, nil
	}
	smart.probeRegistry = registry
	smart.candidateProbeKey = map[string]string{fast.Tag(): fast.Tag(), slow.Tag(): slow.Tag()}
	done := make(chan struct{})
	go func() {
		_, _ = smart.probe(context.Background())
		close(done)
	}()
	deadline := time.Now().Add(time.Second)
	for {
		status := smart.SmartStatus()
		if len(status.Candidates) > 0 && status.Candidates[0].Samples > 0 {
			break
		}
		if time.Now().After(deadline) {
			close(releaseSlow)
			t.Fatal("first successful basic probe was not published while the cycle remained active")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-done:
		t.Fatal("probe cycle completed before the blocked candidate was released")
	default:
	}
	close(releaseSlow)
	<-done
}

func TestSmartProbeCoversEveryCandidateRegardlessOfGroupSize(t *testing.T) {
	candidates := make([]adapter.Outbound, 128)
	fakes := make([]*smartFakeOutbound, len(candidates))
	for index := range candidates {
		fakes[index] = newSmartFakeOutbound("probe-all-"+strconv.Itoa(index), errors.New("offline"))
		candidates[index] = fakes[index]
	}
	smart := newTestSmart(candidates...)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _ = smart.probe(ctx)
	for index, candidate := range fakes {
		if candidate.dials.Load() != 1 {
			t.Fatalf("candidate %d was probed %d times", index, candidate.dials.Load())
		}
	}
}

type smartObservedTestPacketConn struct {
	response []byte
}

func (c *smartObservedTestPacketConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	if len(c.response) == 0 {
		return 0, nil, net.ErrClosed
	}
	count := copy(payload, c.response)
	return count, &net.UDPAddr{}, nil
}

func (*smartObservedTestPacketConn) WriteTo(payload []byte, _ net.Addr) (int, error) {
	return len(payload), nil
}

func (*smartObservedTestPacketConn) Close() error                     { return nil }
func (*smartObservedTestPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*smartObservedTestPacketConn) SetDeadline(time.Time) error      { return nil }
func (*smartObservedTestPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*smartObservedTestPacketConn) SetWriteDeadline(time.Time) error { return nil }

func TestSmartTransactionalUDPNoResponseReportsOnce(t *testing.T) {
	var failures atomic.Int64
	conn := newSmartObservedPacketConn(&smartObservedTestPacketConn{}, time.Now().Add(-2*time.Second), true, func(time.Duration) {
		failures.Add(1)
	})
	if _, err := conn.WriteTo([]byte("quic"), &net.UDPAddr{}); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if failures.Load() != 1 {
		t.Fatalf("transactional UDP failure count=%d, want 1", failures.Load())
	}
}

func TestSmartUDPResponseAndOneWayTrafficDoNotFail(t *testing.T) {
	for _, test := range []struct {
		name           string
		expectResponse bool
		response       []byte
	}{
		{name: "transaction received response", expectResponse: true, response: []byte("ok")},
		{name: "one way UDP", expectResponse: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var failures atomic.Int64
			conn := newSmartObservedPacketConn(&smartObservedTestPacketConn{response: test.response}, time.Now().Add(-2*time.Second), test.expectResponse, func(time.Duration) {
				failures.Add(1)
			})
			if _, err := conn.WriteTo([]byte("payload"), &net.UDPAddr{}); err != nil {
				t.Fatal(err)
			}
			if len(test.response) > 0 {
				buffer := make([]byte, 16)
				if _, _, err := conn.ReadFrom(buffer); err != nil {
					t.Fatal(err)
				}
			}
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			if failures.Load() != 0 {
				t.Fatalf("false UDP failure count=%d", failures.Load())
			}
		})
	}
}

func TestSmartBrokenPermanentPinIsRetained(t *testing.T) {
	first := newSmartFakeOutbound("first", errors.New("dial failed"))
	second := newSmartFakeOutbound("second", nil)
	smart := newTestSmart(first, second)
	if !smart.SelectOutbound("first") {
		t.Fatal("failed to pin first")
	}

	conn, err := smart.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("example.com:443"))
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	peer := <-second.peers
	peer.Close()
	status := smart.SmartStatus()
	if status.Pinned != "first" {
		t.Fatalf("expected permanent pin retained, got %q", status.Pinned)
	}
}

func TestSmartUnstartedHalfOpenAttemptReleasesReservation(t *testing.T) {
	first := newSmartFakeOutbound("first", nil)
	second := newSmartFakeOutbound("second", nil)
	smart := newTestSmart(first, second)
	ranks := []smartRank{
		{outbound: first, eligible: true, status: adapter.SmartCandidateStatus{State: "healthy"}},
		{outbound: second, eligible: true, status: adapter.SmartCandidateStatus{State: "half_open"}},
	}
	attempts := smart.collectDialAttempts(ranks, "network", "site", N.NetworkTCP)
	conn, _, _, ok := smart.dialContextAdaptive(context.Background(), N.NetworkTCP, M.ParseSocksaddr("example.com:443"), attempts, "network", "site", N.NetworkTCP)
	if !ok {
		t.Fatal("expected first attempt to succeed")
	}
	conn.Close()
	peer := <-first.peers
	peer.Close()
	smart.access.Lock()
	defer smart.access.Unlock()
	if len(smart.halfOpen) != 0 {
		t.Fatalf("unstarted half-open reservation leaked: %d", len(smart.halfOpen))
	}
}

func TestSmartSiteAffinityPreventsMinorOscillation(t *testing.T) {
	first := newSmartFakeOutbound("first", nil)
	second := newSmartFakeOutbound("second", nil)
	smart := newTestSmart(first, second)
	now := time.Now()
	networkKey := smart.networkFingerprint()
	siteDisplay, siteKey := smartSiteIdentity(nil, M.ParseSocksaddr("video.example:443"))
	for range 10 {
		smart.store.observeDial(now, networkKey, siteKey, "first", N.NetworkTCP, true, 100*time.Millisecond)
		smart.store.observeDial(now, networkKey, siteKey, "second", N.NetworkTCP, true, 95*time.Millisecond)
	}
	initialRanks, _, _, _ := smart.rank(context.Background(), N.NetworkTCP, M.ParseSocksaddr("video.example:443"))
	smart.markSelected(first, networkKey, siteKey, siteDisplay, N.NetworkTCP, initialRanks, 0)
	ranks, _, _, _ := smart.rank(context.Background(), N.NetworkTCP, M.ParseSocksaddr("video.example:443"))
	if ranks[0].outbound.Tag() != "first" {
		t.Fatalf("expected affinity to retain first, got %s", ranks[0].outbound.Tag())
	}
}

func TestSmartHealthyCandidateRequiresSustainedImprovementBeforeSwitch(t *testing.T) {
	first := newSmartFakeOutbound("first", nil)
	second := newSmartFakeOutbound("second", nil)
	smart := newTestSmart(first, second)
	smart.switchConfirm = 20 * time.Millisecond
	smart.switchMargin = 0
	now := time.Now()
	networkKey := smart.networkFingerprint()
	destination := M.ParseSocksaddr("search.example:443")
	siteDisplay, siteKey := smartSiteIdentity(nil, destination)
	for range 10 {
		smart.store.observeDial(now, networkKey, siteKey, first.Tag(), N.NetworkTCP, true, 200*time.Millisecond)
		smart.store.observeDial(now, networkKey, siteKey, second.Tag(), N.NetworkTCP, true, 20*time.Millisecond)
	}
	smart.markSelected(first, networkKey, siteKey, siteDisplay, N.NetworkTCP, nil, 0)
	ranks, _, _, _ := smart.rank(context.Background(), N.NetworkTCP, destination)
	if ranks[0].outbound.Tag() != first.Tag() {
		t.Fatalf("healthy current candidate switched immediately to %s", ranks[0].outbound.Tag())
	}
	time.Sleep(25 * time.Millisecond)
	ranks, _, _, _ = smart.rank(context.Background(), N.NetworkTCP, destination)
	if ranks[0].outbound.Tag() != second.Tag() {
		t.Fatalf("sustained better candidate was not selected: %s", ranks[0].outbound.Tag())
	}
}

func TestSmartDialFailureBypassesLazySwitchConfirmation(t *testing.T) {
	first := newSmartFakeOutbound("first", nil)
	second := newSmartFakeOutbound("second", nil)
	smart := newTestSmart(first, second)
	destination := M.ParseSocksaddr("search.example:443")
	networkKey := smart.networkFingerprint()
	siteDisplay, siteKey := smartSiteIdentity(nil, destination)
	smart.markSelected(first, networkKey, siteKey, siteDisplay, N.NetworkTCP, nil, 0)
	first.dialError = errors.New("node unavailable")
	conn, err := smart.DialContext(context.Background(), N.NetworkTCP, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	defer (<-second.peers).Close()
	if first.dials.Load() != 1 || second.dials.Load() != 1 {
		t.Fatalf("failure did not fail over in the same request: first=%d second=%d", first.dials.Load(), second.dials.Load())
	}
}

func TestSmartPerformanceSwitchKeepsEstablishedConnection(t *testing.T) {
	first := newSmartFakeOutbound("first", nil)
	second := newSmartFakeOutbound("second", nil)
	smart := newTestSmart(first, second)
	smart.interruptMode = "selective"
	networkKey := "network"
	siteKey := "site"
	smart.markSelected(first, networkKey, siteKey, "example.com", N.NetworkTCP, nil, 0)
	left, right := net.Pipe()
	defer right.Close()
	wrapped := smart.interruptGroup.NewConnWithKey(left, true, false, smartConnectionKey(networkKey, siteKey, N.NetworkTCP, first.Tag()))
	defer wrapped.Close()
	smart.markSelected(second, networkKey, siteKey, "example.com", N.NetworkTCP, nil, 0)
	_ = right.SetWriteDeadline(time.Now().Add(time.Second))
	_ = wrapped.SetReadDeadline(time.Now().Add(time.Second))
	go func() { _, _ = right.Write([]byte{1}) }()
	buffer := make([]byte, 1)
	if _, err := wrapped.Read(buffer); err != nil {
		t.Fatalf("performance switch interrupted established connection: %v", err)
	}
	if smart.connectionsInterrupted.Load() != 0 {
		t.Fatalf("performance switch reported interrupted connections: %d", smart.connectionsInterrupted.Load())
	}
}

func TestSmartSiteIdentityUsesSniffHostForIPDestination(t *testing.T) {
	metadata := &adapter.InboundContext{SniffHost: "www.google.com"}
	display, key := smartSiteIdentity(metadata, M.ParseSocksaddr("142.251.156.119:443"))
	if display != "service:google" || key == "" {
		t.Fatalf("sniffed host was not inherited: display=%q key=%q", display, key)
	}
}

func TestSmartGoogleServiceFamilySharesAffinityIdentity(t *testing.T) {
	hosts := []string{
		"www.google.com", "accounts.google.com", "www.googleapis.com",
		"ssl.gstatic.com", "lh3.googleusercontent.com", "mtalk.google.com", "mail.google.com",
	}
	var expectedKey string
	for _, host := range hosts {
		display, key := smartSiteIdentity(nil, M.ParseSocksaddr(host+":443"))
		if display != "service:google" {
			t.Fatalf("Google host %s resolved to %q", host, display)
		}
		if expectedKey == "" {
			expectedKey = key
		} else if key != expectedKey {
			t.Fatalf("Google host %s split affinity: %s != %s", host, key, expectedKey)
		}
	}
}

func TestSmartGoogleProductsKeepIndependentFamilies(t *testing.T) {
	tests := map[string]string{
		"www.youtube.com":                   "service:youtube",
		"r1.googlevideo.com":                "service:youtube",
		"gemini.google.com":                 "service:gemini",
		"generativelanguage.googleapis.com": "service:gemini",
	}
	keys := make(map[string]string)
	for host, expected := range tests {
		display, key := smartSiteIdentity(nil, M.ParseSocksaddr(host+":443"))
		if display != expected {
			t.Fatalf("host %s resolved to %q, want %q", host, display, expected)
		}
		keys[expected] = key
	}
	if keys["service:youtube"] == keys["service:gemini"] {
		t.Fatal("YouTube and Gemini unexpectedly share one affinity family")
	}
}

func TestSmartRanksTCPAndUDPIndependently(t *testing.T) {
	first := newSmartFakeOutboundNetworks("first", []string{N.NetworkTCP, N.NetworkUDP}, nil)
	second := newSmartFakeOutboundNetworks("second", []string{N.NetworkTCP, N.NetworkUDP}, nil)
	smart := newTestSmart(first, second)
	now := time.Now()
	networkKey := smart.networkFingerprint()
	_, siteKey := smartSiteIdentity(nil, M.ParseSocksaddr("game.example:443"))
	for range 10 {
		smart.store.observeDial(now, networkKey, siteKey, "first", N.NetworkTCP, true, 30*time.Millisecond)
		smart.store.observeDial(now, networkKey, siteKey, "second", N.NetworkTCP, true, 100*time.Millisecond)
		smart.store.observeDial(now, networkKey, siteKey, "second", N.NetworkUDP, true, 35*time.Millisecond)
	}
	smart.store.breakerFailures = 3
	for range 3 {
		smart.store.observeDial(now, networkKey, siteKey, "first", N.NetworkUDP, false, time.Second)
	}
	tcpRanks, _, _, _ := smart.rank(context.Background(), N.NetworkTCP, M.ParseSocksaddr("game.example:443"))
	udpRanks, _, _, _ := smart.rank(context.Background(), N.NetworkUDP, M.ParseSocksaddr("game.example:443"))
	if tcpRanks[0].outbound.Tag() != "first" {
		t.Fatalf("expected first for TCP, got %s", tcpRanks[0].outbound.Tag())
	}
	if udpRanks[0].outbound.Tag() != "second" {
		t.Fatalf("expected second for UDP, got %s", udpRanks[0].outbound.Tag())
	}
}

func TestSmartBulkSitePrefersSustainedThroughput(t *testing.T) {
	lowLatency := newSmartFakeOutbound("low-latency", nil)
	highThroughput := newSmartFakeOutbound("high-throughput", nil)
	smart := newTestSmart(lowLatency, highThroughput)
	now := time.Now()
	networkKey := smart.networkFingerprint()
	destination := M.ParseSocksaddr("video.example:443")
	_, siteKey := smartSiteIdentity(nil, destination)
	for range 12 {
		smart.store.observeDial(now, networkKey, siteKey, lowLatency.Tag(), N.NetworkTCP, true, 25*time.Millisecond)
		smart.store.observeDial(now, networkKey, siteKey, highThroughput.Tag(), N.NetworkTCP, true, 130*time.Millisecond)
	}
	for range 3 {
		smart.store.observeThroughput(now, networkKey, siteKey, lowLatency.Tag(), N.NetworkTCP, 512*1024, 2*time.Second)
		smart.store.observeThroughput(now, networkKey, siteKey, highThroughput.Tag(), N.NetworkTCP, 64*1024*1024, 2*time.Second)
	}
	ranks, _, _, _ := smart.rank(context.Background(), N.NetworkTCP, destination)
	if ranks[0].profile != smartProfileBulk {
		t.Fatalf("expected bulk profile, got %s", ranks[0].profile)
	}
	if ranks[0].outbound.Tag() != highThroughput.Tag() {
		t.Fatalf("expected high-throughput candidate, got %s", ranks[0].outbound.Tag())
	}
	unrelatedRanks, _, _, _ := smart.rank(context.Background(), N.NetworkTCP, M.ParseSocksaddr("bank.example:443"))
	if unrelatedRanks[0].profile != smartProfileInteractive {
		t.Fatalf("bulk profile leaked to an unrelated site: %s", unrelatedRanks[0].profile)
	}
}

func TestSmartProbeSuppressesCommonFailure(t *testing.T) {
	first := newSmartFakeOutbound("first", errors.New("offline"))
	second := newSmartFakeOutbound("second", errors.New("offline"))
	smart := newTestSmart(first, second)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := smart.probe(ctx); err == nil {
		t.Fatal("expected all-probe failure")
	}
	networkKey := smart.networkFingerprint()
	for _, candidate := range []string{"first", "second"} {
		estimate := smart.store.estimate(time.Now(), networkKey, "", candidate, N.NetworkTCP, smart.minSamples)
		if estimate.State != "unknown" {
			t.Fatalf("common failure penalized %s: %s", candidate, estimate.State)
		}
	}
}

func TestSmartHalfOpenAllowsOneRecoveryTrial(t *testing.T) {
	candidate := newSmartFakeOutbound("candidate", nil)
	smart := newTestSmart(candidate)
	rank := smartRank{
		outbound: candidate,
		status: adapter.SmartCandidateStatus{
			State: "half_open",
		},
	}
	if !smart.reserveHalfOpen(rank, "network", "site", N.NetworkTCP) {
		t.Fatal("first half-open trial was not reserved")
	}
	if smart.reserveHalfOpen(rank, "network", "site", N.NetworkTCP) {
		t.Fatal("second concurrent half-open trial was admitted")
	}
	smart.releaseHalfOpen(candidate.Tag(), "network", "site", N.NetworkTCP)
	if !smart.reserveHalfOpen(rank, "network", "site", N.NetworkTCP) {
		t.Fatal("half-open trial did not become available after release")
	}
}

func TestSmartObservedConnKeepsExtendedCounters(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	var firstByte atomic.Int32
	var closedBytes atomic.Int64
	observed := newSmartObservedConn(local, time.Now(), func(time.Duration) {
		firstByte.Add(1)
	}, func(bytes int64, _ time.Duration) {
		closedBytes.Store(bytes)
	})
	if _, loaded := observed.(N.ExtendedConn); !loaded {
		t.Fatal("observed connection lost ExtendedConn support")
	}
	if _, loaded := observed.(N.ReadCounter); !loaded {
		t.Fatal("observed connection does not expose read counters")
	}
	if _, loaded := observed.(N.WriteCounter); !loaded {
		t.Fatal("observed connection does not expose write counters")
	}
	go func() {
		_, _ = peer.Write([]byte("reply"))
	}()
	buffer := make([]byte, 5)
	if _, err := observed.Read(buffer); err != nil {
		t.Fatal(err)
	}
	go func() {
		readBuffer := make([]byte, 7)
		_, _ = peer.Read(readBuffer)
	}()
	if _, err := observed.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := observed.Close(); err != nil {
		t.Fatal(err)
	}
	if firstByte.Load() != 1 {
		t.Fatalf("first byte observed %d times", firstByte.Load())
	}
	if closedBytes.Load() != 12 {
		t.Fatalf("unexpected observed byte count: %d", closedBytes.Load())
	}
}

func TestSmartRanksLargeCandidatePool(t *testing.T) {
	const candidateCount = 1000
	candidates := make([]adapter.Outbound, 0, candidateCount)
	for index := range candidateCount {
		candidates = append(candidates, newSmartFakeOutbound("candidate-"+strconv.Itoa(index), nil))
	}
	smart := newTestSmart(candidates...)
	now := time.Now()
	networkKey := smart.networkFingerprint()
	destination := M.ParseSocksaddr("pool.example:443")
	_, siteKey := smartSiteIdentity(nil, destination)
	for range 20 {
		smart.store.observeDial(now, networkKey, siteKey, "candidate-999", N.NetworkTCP, true, 15*time.Millisecond)
	}
	ranks, _, _, _ := smart.rank(context.Background(), N.NetworkTCP, destination)
	if len(ranks) != candidateCount {
		t.Fatalf("expected %d candidates, got %d", candidateCount, len(ranks))
	}
	if ranks[0].outbound.Tag() != "candidate-999" {
		t.Fatalf("known healthy candidate did not lead the pool: %s", ranks[0].outbound.Tag())
	}
	status := smart.SmartStatus()
	if status.CandidateCount != candidateCount {
		t.Fatalf("status candidate count mismatch: %d", status.CandidateCount)
	}
	if len(status.Candidates) != smartStatusCandidateLimit {
		t.Fatalf("status snapshot was not bounded: %d", len(status.Candidates))
	}
}

func TestSmartNestedGroupsExpandToUniqueLeaves(t *testing.T) {
	leafA := newSmartFakeOutbound("leaf-a", nil)
	leafB := newSmartFakeOutbound("leaf-b", nil)
	groupA := &smartFakeGroup{
		smartFakeOutbound: newSmartFakeOutbound("group-a", nil),
		children:          []string{"leaf-a", "group-b"},
	}
	groupB := &smartFakeGroup{
		smartFakeOutbound: newSmartFakeOutbound("group-b", nil),
		children:          []string{"leaf-b", "group-a", "leaf-a"},
	}
	manager := &smartFakeOutboundManager{byTag: map[string]adapter.Outbound{
		"leaf-a":  leafA,
		"leaf-b":  leafB,
		"group-a": groupA,
		"group-b": groupB,
	}}
	smart := newTestSmart()
	smart.outbound = manager
	var leaves []adapter.Outbound
	smart.flattenCandidate(groupA, make(map[string]bool), make(map[string]bool), &leaves)
	if len(leaves) != 2 {
		t.Fatalf("expected two unique leaves, got %d", len(leaves))
	}
	if leaves[0].Tag() != "leaf-a" || leaves[1].Tag() != "leaf-b" {
		t.Fatalf("unexpected leaf order: %s, %s", leaves[0].Tag(), leaves[1].Tag())
	}
}

func TestSmartManualNodeExclusionFiltersNestedLeaves(t *testing.T) {
	keep := newSmartFakeOutbound("airport/美国-普通节点", nil)
	excludedKeyword := newSmartFakeOutbound("airport/美国-Gcore-01", nil)
	excludedExact := newSmartFakeOutbound("airport/完整节点名", nil)
	group := &smartFakeGroup{
		smartFakeOutbound: newSmartFakeOutbound("provider/group", nil),
		children:          []string{keep.Tag(), excludedKeyword.Tag(), excludedExact.Tag()},
	}
	manager := &smartFakeOutboundManager{byTag: map[string]adapter.Outbound{
		keep.Tag(): keep, excludedKeyword.Tag(): excludedKeyword, excludedExact.Tag(): excludedExact, group.Tag(): group,
	}}
	matcher, err := nodefilter.New([]string{"Gcore", "=" + excludedExact.Tag()})
	if err != nil {
		t.Fatal(err)
	}
	smart := newTestSmart()
	smart.outbound = manager
	smart.manualExclude = matcher
	var leaves []adapter.Outbound
	smart.flattenCandidate(group, make(map[string]bool), make(map[string]bool), &leaves)
	if len(leaves) != 1 || leaves[0].Tag() != keep.Tag() {
		t.Fatalf("manual exclusion did not filter nested leaves: %+v", leaves)
	}
}

func TestSmartNetworkFingerprintUsesSubnetAndDNS(t *testing.T) {
	base := &adapter.NetworkInterface{
		Interface: control.Interface{
			Index:        2,
			MTU:          1500,
			Name:         "eth0",
			HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
			Addresses: []netip.Prefix{
				netip.MustParsePrefix("2001:db8:1::1234/64"),
				netip.MustParsePrefix("192.0.2.20/24"),
			},
		},
		Type:       C.InterfaceTypeEthernet,
		DNSServers: []string{"1.1.1.1", "8.8.8.8"},
	}
	reordered := *base
	reordered.Addresses = []netip.Prefix{
		netip.MustParsePrefix("192.0.2.99/24"),
		netip.MustParsePrefix("2001:db8:1::abcd/64"),
	}
	reordered.DNSServers = []string{"8.8.8.8", "1.1.1.1"}
	first := smartNetworkFingerprint(base, adapter.WIFIState{})
	second := smartNetworkFingerprint(&reordered, adapter.WIFIState{})
	if first != second {
		t.Fatal("address or DNS ordering changed the network fingerprint")
	}
	otherSubnet := reordered
	otherSubnet.Addresses = []netip.Prefix{netip.MustParsePrefix("198.51.100.20/24")}
	if first == smartNetworkFingerprint(&otherSubnet, adapter.WIFIState{}) {
		t.Fatal("different subnet reused the same network fingerprint")
	}
	if first == smartNetworkFingerprint(base, adapter.WIFIState{SSID: "other-network"}) {
		t.Fatal("different Wi-Fi identity reused the same network fingerprint")
	}
}

func BenchmarkSmartRankCandidatePools(b *testing.B) {
	for _, candidateCount := range []int{100, 500, 1000} {
		b.Run(strconv.Itoa(candidateCount), func(b *testing.B) {
			candidates := make([]adapter.Outbound, 0, candidateCount)
			for index := range candidateCount {
				candidates = append(candidates, newSmartFakeOutbound("candidate-"+strconv.Itoa(index), nil))
			}
			smart := newTestSmart(candidates...)
			destination := M.ParseSocksaddr("benchmark.example:443")
			b.ResetTimer()
			for b.Loop() {
				ranks, _, _, _ := smart.rank(context.Background(), N.NetworkTCP, destination)
				if len(ranks) != candidateCount {
					b.Fatal("candidate count changed")
				}
			}
		})
	}
}
