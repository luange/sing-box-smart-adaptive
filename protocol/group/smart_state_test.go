package group

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/protocol/group/probe"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestSmartProbeUsesOnlyConnectivity204(t *testing.T) {
	leaf := &smartCloseStubOutbound{Adapter: outbound.NewAdapter(C.TypeDirect, "leaf", []string{N.NetworkTCP}, nil)}
	var access sync.Mutex
	var links []string
	registry := &smartProbeRegistry{
		ctx:     context.Background(),
		cancel:  func() {},
		entries: make(map[string]*smartProbeEntry),
		slots:   make(chan struct{}, 1),
		probe: func(_ context.Context, link string, _ adapter.Outbound) (uint16, error) {
			access.Lock()
			links = append(links, link)
			access.Unlock()
			return 7, nil
		},
	}
	smart := &Smart{
		ctx:               context.Background(),
		control:           &smartControlState{},
		store:             newSmartStore(time.Hour, 3, time.Minute),
		probeURL:          probe.GoogleConnectivityURL,
		probeInterval:     time.Minute,
		probeCycleTimeout: time.Second,
		probeTimeout:      time.Second,
		probeRegistry:     registry,
		candidates:        []adapter.Outbound{leaf},
		candidateByTag:    map[string]adapter.Outbound{"leaf": leaf},
		candidateProbeKey: map[string]string{"leaf": "endpoint-id"},
		lastSelected:      make(map[string]string),
		affinity:          make(map[string]smartAffinity),
		switchChallenges:  make(map[string]smartSwitchChallenge),
		halfOpen:          make(map[string]struct{}),
	}
	delays, err := smart.probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if delays["leaf"] != 7 {
		t.Fatalf("unexpected probe delay: %v", delays)
	}
	access.Lock()
	defer access.Unlock()
	if len(links) != 1 || links[0] != probe.GoogleConnectivityURL {
		t.Fatalf("Smart must probe only the connectivity 204 target, got %v", links)
	}
}

func TestSmartProbeScheduleFollowsTrafficActivity(t *testing.T) {
	smart := &Smart{
		probeInterval: 10 * time.Minute,
		probeNow:      make(chan struct{}, 1),
	}
	now := time.Now()
	if smart.activeAt(now) {
		t.Fatal("new Smart group must start idle")
	}
	if interval := smart.nextProbeInterval(now); interval != defaultSmartIdleProbeInterval {
		t.Fatalf("idle interval = %v, want %v", interval, defaultSmartIdleProbeInterval)
	}
	if budget := smart.scheduledProbeBudget(now); budget != 1 {
		t.Fatalf("idle scheduled budget = %d, want 1", budget)
	}
	if budget := smart.requestedProbeBudget(now); budget != defaultSmartColdProbeBudget {
		t.Fatalf("cold requested budget = %d, want %d", budget, defaultSmartColdProbeBudget)
	}

	smart.noteTrafficActivity()
	now = time.Now()
	if !smart.activeAt(now) {
		t.Fatal("real traffic did not wake Smart profiling")
	}
	if interval := smart.nextProbeInterval(now); interval != smart.probeInterval {
		t.Fatalf("active interval = %v, want %v", interval, smart.probeInterval)
	}
	if budget := smart.scheduledProbeBudget(now); budget != defaultSmartActiveProbeBudget {
		t.Fatalf("active scheduled budget = %d, want %d", budget, defaultSmartActiveProbeBudget)
	}
	select {
	case <-smart.probeNow:
	default:
		t.Fatal("first real traffic did not request an immediate profile cycle")
	}

	// Additional traffic inside the activity window must not enqueue a probe
	// per connection; that would turn a busy group into a probe storm.
	smart.noteTrafficActivity()
	select {
	case <-smart.probeNow:
		t.Fatal("active traffic enqueued a duplicate immediate probe")
	default:
	}

	smart.lastActivityUnixNano.Store(time.Now().Add(-defaultSmartActivityWindow - time.Second).UnixNano())
	smart.noteTrafficActivity()
	select {
	case <-smart.probeNow:
	default:
		t.Fatal("traffic after idle did not wake Smart profiling")
	}
}

func TestSmartProbeBudgetRotatesWithoutOverlap(t *testing.T) {
	registry := &smartProbeRegistry{
		ctx:     context.Background(),
		cancel:  func() {},
		entries: make(map[string]*smartProbeEntry),
		slots:   make(chan struct{}, 5),
		probe: func(_ context.Context, _ string, _ adapter.Outbound) (uint16, error) {
			return 10, nil
		},
	}
	candidates := make([]adapter.Outbound, 10)
	byTag := make(map[string]adapter.Outbound, len(candidates))
	probeKeys := make(map[string]string, len(candidates))
	for index := range candidates {
		tag := "node-" + itoaSmall(index)
		leaf := &smartCloseStubOutbound{Adapter: outbound.NewAdapter(C.TypeDirect, tag, []string{N.NetworkTCP}, nil)}
		candidates[index] = leaf
		byTag[tag] = leaf
		probeKeys[tag] = tag
	}
	smart := &Smart{
		ctx:               context.Background(),
		control:           &smartControlState{},
		store:             newSmartStore(time.Hour, 3, time.Minute),
		probeURL:          probe.GoogleConnectivityURL,
		probeInterval:     time.Minute,
		probeTimeout:      time.Second,
		probeRegistry:     registry,
		candidates:        candidates,
		candidateByTag:    byTag,
		candidateProbeKey: probeKeys,
		lastSelected:      make(map[string]string),
		affinity:          make(map[string]smartAffinity),
		switchChallenges:  make(map[string]smartSwitchChallenge),
		halfOpen:          make(map[string]struct{}),
	}
	first, err := smart.probeWithBudget(context.Background(), 4)
	if err != nil {
		t.Fatal(err)
	}
	second, err := smart.probeWithBudget(context.Background(), 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 4 || len(second) != 4 {
		t.Fatalf("unexpected budget result sizes: first=%d second=%d", len(first), len(second))
	}
	for tag := range first {
		if _, exists := second[tag]; exists {
			t.Fatalf("consecutive rotating windows overlapped on %s", tag)
		}
	}
	if cursor := smart.probeCursor.Load(); cursor != 8 {
		t.Fatalf("probe cursor = %d, want 8", cursor)
	}
}

func TestSmartReliabilityUsesConfidence(t *testing.T) {
	store := newSmartStore(time.Hour, 3, time.Minute)
	now := time.Unix(1000, 0)
	initial := store.estimate(now, "eth0", "", "a", "tcp", 3)
	store.observeDial(now, "eth0", "", "a", "tcp", true, 100*time.Millisecond)
	oneSuccess := store.estimate(now, "eth0", "", "a", "tcp", 3)
	for range 20 {
		store.observeDial(now, "eth0", "", "a", "tcp", true, 100*time.Millisecond)
	}
	manySuccesses := store.estimate(now, "eth0", "", "a", "tcp", 3)
	if !(initial.Reliability < oneSuccess.Reliability && oneSuccess.Reliability < manySuccesses.Reliability) {
		t.Fatalf("unexpected reliability ordering: initial=%f one=%f many=%f", initial.Reliability, oneSuccess.Reliability, manySuccesses.Reliability)
	}
}

func TestSmartConnectivity204RTTFeedsEWMAAndJitter(t *testing.T) {
	store := newSmartStore(time.Hour, 3, time.Minute)
	now := time.Now()
	store.observeDial(now, "network", "", "node", N.NetworkTCP, true, 100*time.Millisecond)
	first := store.estimate(now, "network", "", "node", N.NetworkTCP, 3)
	store.observeDial(now.Add(time.Second), "network", "", "node", N.NetworkTCP, true, 300*time.Millisecond)
	second := store.estimate(now.Add(time.Second), "network", "", "node", N.NetworkTCP, 3)
	if !first.HasConnect || first.ConnectMS != 100 {
		t.Fatalf("first connectivity RTT was not recorded: %+v", first)
	}
	if second.ConnectMS <= first.ConnectMS || second.ConnectMS >= 300 {
		t.Fatalf("connectivity RTT must be smoothed by EWMA: first=%f second=%f", first.ConnectMS, second.ConnectMS)
	}
	if second.JitterMS <= 0 {
		t.Fatalf("connectivity RTT variation must update jitter: %+v", second)
	}
}

func TestSmartBreakerHalfOpenAndRecovery(t *testing.T) {
	store := newSmartStore(time.Hour, 3, time.Minute)
	now := time.Unix(2000, 0)
	for range 3 {
		store.observeDial(now, "eth0", "example.com", "a", "tcp", false, time.Second)
	}
	open := store.estimate(now, "eth0", "example.com", "a", "tcp", 3)
	if open.State != "open" {
		t.Fatalf("expected open, got %s", open.State)
	}
	halfOpen := store.estimate(now.Add(time.Minute+time.Second), "eth0", "example.com", "a", "tcp", 3)
	if halfOpen.State != "half_open" {
		t.Fatalf("expected half_open, got %s", halfOpen.State)
	}
	store.observeDial(now.Add(time.Minute+time.Second), "eth0", "example.com", "a", "tcp", true, 80*time.Millisecond)
	recovered := store.estimate(now.Add(time.Minute+time.Second), "eth0", "example.com", "a", "tcp", 3)
	if recovered.State == "open" || recovered.State == "half_open" {
		t.Fatalf("expected recovered state, got %s", recovered.State)
	}
}

func TestSmartSiteHistoryOverridesGlobalGradually(t *testing.T) {
	store := newSmartStore(time.Hour, 3, time.Minute)
	now := time.Unix(3000, 0)
	for range 20 {
		store.observeDial(now, "eth0", "", "a", "tcp", true, 50*time.Millisecond)
	}
	for range 6 {
		store.observeDial(now, "eth0", "video.example", "a", "tcp", false, time.Second)
	}
	global := store.estimate(now, "eth0", "", "a", "tcp", 3)
	site := store.estimate(now, "eth0", "video.example", "a", "tcp", 3)
	if site.Reliability >= global.Reliability {
		t.Fatalf("site reliability should be lower: site=%f global=%f", site.Reliability, global.Reliability)
	}
}

func TestSmartThroughputAffectsScore(t *testing.T) {
	slow := smartEstimate{
		Reliability:   0.99,
		ConnectMS:     80,
		ThroughputBPS: 512 * 1024,
		Samples:       10,
		State:         "healthy",
		HasConnect:    true,
		HasThroughput: true,
	}
	fast := slow
	fast.ThroughputBPS = 32 * 1024 * 1024
	if smartScoreForProfile(fast, smartProfileBulk, 0, 20) >= smartScoreForProfile(slow, smartProfileBulk, 0, 20) {
		t.Fatal("faster candidate should have a lower score")
	}
}

func TestSmartSiteFailuresDoNotOpenGlobalCircuit(t *testing.T) {
	store := newSmartStore(time.Hour, 3, time.Minute)
	now := time.Unix(4000, 0)
	for range 3 {
		store.observeDial(now, "wifi", "bank.example", "a", "tcp", false, time.Second)
	}
	global := store.estimate(now, "wifi", "", "a", "tcp", 3)
	site := store.estimate(now, "wifi", "bank.example", "a", "tcp", 3)
	if global.State == "open" {
		t.Fatal("site-specific failures opened the global circuit")
	}
	if site.State != "open" {
		t.Fatalf("expected the site circuit to open, got %s", site.State)
	}
}

func TestSmartCrossSiteFailureBurstOpensGlobalCircuit(t *testing.T) {
	store := newSmartStore(time.Hour, 3, 2*time.Minute)
	now := time.Unix(5000, 0)
	store.observeDial(now, "wifi", "api-a.example", "node-a", "tcp", false, time.Second)
	store.observeDial(now.Add(20*time.Second), "wifi", "api-a.example", "node-a", "tcp", false, time.Second)
	store.observeDial(now.Add(40*time.Second), "wifi", "api-b.example", "node-a", "tcp", false, time.Second)
	global := store.estimate(now.Add(40*time.Second), "wifi", "", "node-a", "tcp", 3)
	if global.State != "open" {
		t.Fatalf("cross-site real failures did not open global circuit: %+v", global)
	}
}

func TestSmartCrossSiteFailureBurstExpires(t *testing.T) {
	store := newSmartStore(time.Hour, 3, time.Minute)
	now := time.Unix(6000, 0)
	store.observeDial(now, "wifi", "api-a.example", "node-a", "tcp", false, time.Second)
	store.observeDial(now.Add(10*time.Second), "wifi", "api-b.example", "node-a", "tcp", false, time.Second)
	store.observeDial(now.Add(2*time.Minute), "wifi", "api-c.example", "node-a", "tcp", false, time.Second)
	global := store.estimate(now.Add(2*time.Minute), "wifi", "", "node-a", "tcp", 3)
	if global.State == "open" {
		t.Fatalf("expired cross-site failures opened global circuit: %+v", global)
	}
}

func TestSmartCrossSiteFailureBurstClearsAfterRecovery(t *testing.T) {
	store := newSmartStore(time.Hour, 3, 2*time.Minute)
	now := time.Unix(7000, 0)
	store.observeDial(now, "wifi", "api-a.example", "node-a", "tcp", false, time.Second)
	store.observeDial(now.Add(time.Second), "wifi", "api-a.example", "node-a", "tcp", false, time.Second)
	store.observeDial(now.Add(2*time.Second), "wifi", "api-b.example", "node-a", "tcp", false, time.Second)
	store.observeDial(now.Add(3*time.Second), "wifi", "api-b.example", "node-a", "tcp", true, 10*time.Millisecond)
	global := store.estimate(now.Add(3*time.Second), "wifi", "", "node-a", "tcp", 3)
	if global.State == "open" || global.State == "half_open" {
		t.Fatalf("successful recovery did not close global circuit: %+v", global)
	}
	store.access.RLock()
	bursts := len(store.failureBursts)
	store.access.RUnlock()
	if bursts != 0 {
		t.Fatalf("successful recovery retained failure burst: %d", bursts)
	}
}

func TestSmartCandidateDeadRequiresRecentGlobalConsecutiveFailures(t *testing.T) {
	store := newSmartStore(time.Hour, 3, time.Minute)
	now := time.Now()
	for range 2 {
		store.observeDial(now, "ethernet", "", "node-a", "tcp", false, time.Second)
	}
	if store.candidateDead("node-a", now) {
		t.Fatal("two failures must not mark candidate dead")
	}
	store.observeDial(now, "ethernet", "", "node-a", "tcp", false, time.Second)
	if !store.candidateDead("node-a", now) {
		t.Fatal("three recent failures must mark candidate dead")
	}
	store.observeDial(now, "ethernet", "", "node-a", "tcp", true, time.Millisecond)
	if store.candidateDead("node-a", now) {
		t.Fatal("success must clear candidate death")
	}
	for range 3 {
		store.observeDial(now.Add(-time.Minute), "ethernet", "", "node-a", "tcp", false, time.Second)
	}
	if store.candidateDead("node-a", now) {
		t.Fatal("stale failures must not mark candidate dead")
	}
}

func TestSmartTCPAndUDPStateAreIndependent(t *testing.T) {
	store := newSmartStore(time.Hour, 3, time.Minute)
	now := time.Unix(5000, 0)
	for range 3 {
		store.observeDial(now, "ethernet", "game.example", "a", "tcp", false, time.Second)
	}
	for range 6 {
		store.observeDial(now, "ethernet", "game.example", "a", "udp", true, 35*time.Millisecond)
	}
	tcp := store.estimate(now, "ethernet", "game.example", "a", "tcp", 3)
	udp := store.estimate(now, "ethernet", "game.example", "a", "udp", 3)
	if tcp.State != "open" {
		t.Fatalf("expected TCP circuit open, got %s", tcp.State)
	}
	if udp.State == "open" || udp.State == "half_open" {
		t.Fatalf("TCP failures contaminated UDP state: %s", udp.State)
	}
}

func TestSmartNetworkHistoryIsIndependent(t *testing.T) {
	store := newSmartStore(time.Hour, 3, time.Minute)
	now := time.Unix(6000, 0)
	for range 3 {
		store.observeDial(now, "wifi", "", "a", "tcp", false, time.Second)
	}
	wifi := store.estimate(now, "wifi", "", "a", "tcp", 3)
	ethernet := store.estimate(now, "ethernet", "", "a", "tcp", 3)
	if wifi.State != "open" {
		t.Fatalf("expected wifi circuit open, got %s", wifi.State)
	}
	if ethernet.State != "unknown" {
		t.Fatalf("new network inherited stale state: %s", ethernet.State)
	}
}

func TestSmartHierarchicalSamplesAreNotDoubleCounted(t *testing.T) {
	store := newSmartStore(time.Hour, 3, time.Minute)
	now := time.Unix(7000, 0)
	for range 5 {
		store.observeDial(now, "ethernet", "video.example", "a", "tcp", true, 50*time.Millisecond)
	}
	estimate := store.estimate(now, "ethernet", "video.example", "a", "tcp", 3)
	if estimate.Samples != 5 {
		t.Fatalf("hierarchical samples were double counted: %f", estimate.Samples)
	}
}

func TestSmartTrafficProfilesPreferDifferentCandidates(t *testing.T) {
	lowLatency := smartEstimate{
		Reliability:       0.98,
		ConnectMS:         25,
		FirstByteMS:       55,
		ThroughputBPS:     512 * 1024,
		ThroughputSamples: 4,
		Samples:           20,
		State:             "healthy",
		HasConnect:        true,
		HasFirstByte:      true,
		HasThroughput:     true,
	}
	highThroughput := lowLatency
	highThroughput.ConnectMS = 130
	highThroughput.FirstByteMS = 180
	highThroughput.ThroughputBPS = 48 * 1024 * 1024
	if smartScoreForProfile(lowLatency, smartProfileInteractive, 0, 40) >= smartScoreForProfile(highThroughput, smartProfileInteractive, 0, 40) {
		t.Fatal("interactive profile should prefer the lower-latency candidate")
	}
	if smartScoreForProfile(highThroughput, smartProfileBulk, 0, 40) >= smartScoreForProfile(lowLatency, smartProfileBulk, 0, 40) {
		t.Fatal("bulk profile should prefer the higher-throughput candidate")
	}
}

func TestSmartDetectsBulkProfileOnlyAfterUsefulSamples(t *testing.T) {
	estimates := map[string]smartEstimate{
		"a": {ThroughputSamples: 1},
		"b": {},
	}
	if profile := detectSmartTrafficProfile("tcp", estimates); profile != smartProfileInteractive {
		t.Fatalf("single throughput sample changed the profile: %s", profile)
	}
	estimate := estimates["a"]
	estimate.ThroughputSamples = 2
	estimates["a"] = estimate
	if profile := detectSmartTrafficProfile("tcp", estimates); profile != smartProfileBulk {
		t.Fatalf("expected bulk profile, got %s", profile)
	}
	if profile := detectSmartTrafficProfile("udp", estimates); profile != smartProfileUDP {
		t.Fatalf("expected UDP profile, got %s", profile)
	}
}

func TestPassiveThroughputFloorUsesOnlyRealTrafficSamples(t *testing.T) {
	base := smartEstimate{ThroughputBPS: 64 * 1024, ThroughputSamples: 3, HasThroughput: true}
	if !passiveThroughputBelowFloor(base, 512*1024, 2) {
		t.Fatal("sustained low real-traffic throughput should trip the passive floor")
	}
	if passiveThroughputBelowFloor(base, 512*1024, 4) {
		t.Fatal("insufficient throughput samples should not trip the passive floor")
	}
	base.ThroughputBPS = 2 * 1024 * 1024
	if passiveThroughputBelowFloor(base, 512*1024, 2) {
		t.Fatal("throughput above the floor was incorrectly degraded")
	}
	base.ThroughputBPS = 2 * 1024 * 1024
	base.LocalThroughputBPS = 64 * 1024
	base.LocalThroughputSamples = 2
	if !passiveThroughputBelowFloor(base, 512*1024, 2) {
		t.Fatal("service-local low throughput must override a fast global history")
	}
	base.HasThroughput = false
	base.ThroughputBPS = 1
	if passiveThroughputBelowFloor(base, 512*1024, 2) {
		t.Fatal("missing passive observations must not degrade a candidate")
	}
}

func TestSmartHistorySnapshotRoundTrip(t *testing.T) {
	store := newSmartStore(time.Hour, 3, time.Minute)
	now := time.Unix(8000, 0)
	for range 5 {
		store.observeDial(now, "ethernet", "video.example", "a", "tcp", true, 45*time.Millisecond)
	}
	store.observeFirstByte(now, "ethernet", "video.example", "a", "tcp", 80*time.Millisecond)
	store.observeThroughput(now, "ethernet", "video.example", "a", "tcp", 32*1024*1024, 2*time.Second)
	snapshot := store.snapshot(now, 24*time.Hour, 100)
	if snapshot.Version != smartStateVersion || len(snapshot.Metrics) == 0 {
		t.Fatal("history snapshot is empty")
	}

	restored := newSmartStore(time.Hour, 3, time.Minute)
	restored.restore(snapshot)
	estimate := restored.estimate(now, "ethernet", "video.example", "a", "tcp", 3)
	if estimate.State != "healthy" {
		t.Fatalf("restored state mismatch: %s", estimate.State)
	}
	if !estimate.HasFirstByte || !estimate.HasThroughput {
		t.Fatal("restored observations are incomplete")
	}

	rejected := newSmartStore(time.Hour, 3, time.Minute)
	snapshot.Version++
	rejected.restore(snapshot)
	if estimate := rejected.estimate(now, "ethernet", "video.example", "a", "tcp", 3); estimate.State != "unknown" {
		t.Fatalf("unsupported history schema was accepted: %s", estimate.State)
	}
}

func TestSmartHistorySnapshotHonorsRetentionAndLimit(t *testing.T) {
	store := newSmartStore(time.Hour, 3, time.Minute)
	now := time.Unix(9000, 0)
	store.observeDial(now.Add(-2*time.Hour), "ethernet", "", "old", "tcp", true, time.Millisecond)
	store.observeDial(now.Add(-time.Minute), "ethernet", "", "new-a", "tcp", true, time.Millisecond)
	store.observeDial(now, "ethernet", "", "new-b", "tcp", true, time.Millisecond)
	snapshot := store.snapshot(now, time.Hour, 1)
	if len(snapshot.Metrics) != 1 {
		t.Fatalf("expected one retained metric, got %d", len(snapshot.Metrics))
	}
	if snapshot.Metrics[0].Candidate != "new-b" {
		t.Fatalf("snapshot did not keep the newest metric: %s", snapshot.Metrics[0].Candidate)
	}
	store.access.RLock()
	liveEntries := len(store.metrics)
	store.access.RUnlock()
	if liveEntries != 1 {
		t.Fatalf("live state was not pruned with snapshot: %d", liveEntries)
	}
}

func TestSmartWorkerStartsOnPostStart(t *testing.T) {
	smart := &Smart{
		ctx:               context.Background(),
		store:             newSmartStore(time.Hour, 3, time.Minute),
		probeInterval:     time.Hour,
		probeTimeout:      time.Millisecond,
		halfLife:          time.Hour,
		breakerFailures:   3,
		breakerCooldown:   time.Minute,
		historyRetention:  time.Hour,
		maxHistoryEntries: 100,
	}
	if err := smart.PostStart(); err != nil {
		t.Fatal(err)
	}
	smart.lifecycleAccess.Lock()
	started := smart.workerStarted
	smart.lifecycleAccess.Unlock()
	if !started {
		t.Fatal("smart worker did not start on PostStart")
	}
	if err := smart.Close(); err != nil {
		t.Fatal(err)
	}
}

type smartCloseStubOutbound struct {
	outbound.Adapter
}

func (s *smartCloseStubOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, net.ErrClosed
}

func (s *smartCloseStubOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

// TestSmartCloseDoesNotBlockIndefinitely ensures HA restart budget: Close must
// return even if the probe worker is slow to observe cancel.
func TestSmartCloseDoesNotBlockIndefinitely(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	block := make(chan struct{})
	registry := &smartProbeRegistry{
		ctx:     ctx,
		cancel:  func() {},
		entries: make(map[string]*smartProbeEntry),
		slots:   make(chan struct{}, 1),
		probe: func(probeCtx context.Context, _ string, _ adapter.Outbound) (uint16, error) {
			select {
			case <-probeCtx.Done():
				return 0, probeCtx.Err()
			case <-block:
				return 1, nil
			}
		},
	}
	// Occupy the single admission slot so run() waits; Close must still finish.
	registry.slots <- struct{}{}
	defer func() { <-registry.slots; close(block) }()

	leaf := &smartCloseStubOutbound{Adapter: outbound.NewAdapter(C.TypeDirect, "leaf", []string{N.NetworkTCP}, nil)}
	smart := &Smart{
		ctx:               ctx,
		store:             newSmartStore(time.Hour, 3, time.Minute),
		probeInterval:     time.Hour,
		probeCycleTimeout: time.Minute,
		probeTimeout:      30 * time.Second,
		halfLife:          time.Hour,
		breakerFailures:   3,
		breakerCooldown:   time.Minute,
		historyRetention:  time.Hour,
		maxHistoryEntries: 100,
		probeRegistry:     registry,
		candidates:        []adapter.Outbound{leaf},
		candidateByTag:    map[string]adapter.Outbound{"leaf": leaf},
		candidateProbeKey: map[string]string{"leaf": "leaf-id"},
	}
	if err := smart.PostStart(); err != nil {
		t.Fatal(err)
	}
	// Give the worker a moment to enter cold-start probe and block on the slot.
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	if err := smart.Close(); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	// Bound is 2s; allow a little scheduling slack.
	if elapsed > 3*time.Second {
		t.Fatalf("smart.Close blocked too long for HA: %v", elapsed)
	}
}

func TestSmartHealthIsPerInstance(t *testing.T) {
	newInstance := func() *Smart {
		return &Smart{
			ctx:               context.Background(),
			store:             newSmartStore(time.Hour, 3, time.Minute),
			control:           &smartControlState{},
			probeInterval:     time.Hour,
			probeTimeout:      time.Millisecond,
			halfLife:          time.Hour,
			breakerFailures:   3,
			breakerCooldown:   time.Minute,
			historyRetention:  time.Hour,
			maxHistoryEntries: 100,
		}
	}
	first := newInstance()
	if err := first.PostStart(); err != nil {
		t.Fatal(err)
	}
	first.store.observeDial(time.Now(), "network", "", "candidate-a", "tcp", true, time.Millisecond)
	first.control.pinned = "candidate-a"
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second := newInstance()
	if err := second.PostStart(); err != nil {
		t.Fatal(err)
	}
	if first.store == second.store {
		t.Fatal("a new smart generation shares the previous health store")
	}
	if second.control.pinned != "" {
		t.Fatalf("a new smart generation inherited a pin: %s", second.control.pinned)
	}
	if estimate := second.store.estimate(time.Now(), "network", "", "candidate-a", "tcp", 1); estimate.State != "unknown" {
		t.Fatalf("a new smart generation inherited observations: %s", estimate.State)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}
