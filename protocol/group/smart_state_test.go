package group

import (
	"context"
	"testing"
	"time"
)

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
