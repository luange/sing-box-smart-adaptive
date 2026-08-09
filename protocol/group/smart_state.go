package group

import (
	"math"
	"sort"
	"sync"
	"time"
)

const smartStateVersion = 1

type smartMetricKey struct {
	Network   string
	Site      string
	Candidate string
	Transport string
}

type smartMetric struct {
	Network             string    `json:"network"`
	Site                string    `json:"site,omitempty"`
	Candidate           string    `json:"candidate"`
	Transport           string    `json:"transport"`
	Successes           float64   `json:"successes"`
	Failures            float64   `json:"failures"`
	ConnectMS           float64   `json:"connect_ms,omitempty"`
	FirstByteMS         float64   `json:"first_byte_ms,omitempty"`
	ThroughputLog       float64   `json:"throughput_log,omitempty"`
	JitterMS            float64   `json:"jitter_ms,omitempty"`
	ConnectSamples      float64   `json:"connect_samples,omitempty"`
	FirstByteSamples    float64   `json:"first_byte_samples,omitempty"`
	ThroughputSamples   float64   `json:"throughput_samples,omitempty"`
	ConsecutiveFailures int       `json:"consecutive_failures,omitempty"`
	CircuitUntil        time.Time `json:"circuit_until,omitempty"`
	LastUpdated         time.Time `json:"last_updated"`
}

type smartStoreSnapshot struct {
	Version int           `json:"version"`
	Metrics []smartMetric `json:"metrics"`
}

type smartEstimate struct {
	Reliability            float64
	ConnectMS              float64
	FirstByteMS            float64
	ThroughputBPS          float64
	ThroughputSamples      float64
	LocalThroughputSamples float64
	JitterMS               float64
	Samples                float64
	State                  string
	CircuitUntil           time.Time
	LastUpdated            time.Time
	HasConnect             bool
	HasFirstByte           bool
	HasThroughput          bool
}

type smartStore struct {
	access          sync.RWMutex
	metrics         map[smartMetricKey]*smartMetric
	halfLife        time.Duration
	breakerFailures int
	breakerCooldown time.Duration
	retention       time.Duration
	maxEntries      int
}

func (s *smartStore) clear() {
	if s == nil {
		return
	}
	s.access.Lock()
	clear(s.metrics)
	// A real connection may finish after the group is retired. Keep a small,
	// writable map for that late observation while releasing the old buckets.
	s.metrics = make(map[smartMetricKey]*smartMetric)
	s.access.Unlock()
}

func newSmartStore(halfLife time.Duration, breakerFailures int, breakerCooldown time.Duration) *smartStore {
	if halfLife <= 0 {
		halfLife = 30 * time.Minute
	}
	if breakerFailures <= 0 {
		breakerFailures = 3
	}
	if breakerCooldown <= 0 {
		breakerCooldown = 2 * time.Minute
	}
	return &smartStore{
		metrics:         make(map[smartMetricKey]*smartMetric),
		halfLife:        halfLife,
		breakerFailures: breakerFailures,
		breakerCooldown: breakerCooldown,
	}
}

func (s *smartStore) setPolicy(halfLife time.Duration, breakerFailures int, breakerCooldown time.Duration) {
	if halfLife <= 0 {
		halfLife = 30 * time.Minute
	}
	if breakerFailures <= 0 {
		breakerFailures = 3
	}
	if breakerCooldown <= 0 {
		breakerCooldown = 2 * time.Minute
	}
	s.access.Lock()
	s.halfLife = halfLife
	s.breakerFailures = breakerFailures
	s.breakerCooldown = breakerCooldown
	s.access.Unlock()
}

func (s *smartStore) setBounds(retention time.Duration, maxEntries int) {
	s.access.Lock()
	s.retention = retention
	s.maxEntries = maxEntries
	s.pruneLocked(time.Now(), retention, maxEntries)
	s.access.Unlock()
}

func (s *smartStore) metric(key smartMetricKey, now time.Time) *smartMetric {
	metric := s.metrics[key]
	if metric == nil {
		if s.maxEntries > 0 && len(s.metrics) >= s.maxEntries {
			target := max(1, s.maxEntries-s.maxEntries/10)
			s.pruneLocked(now, s.retention, target)
			if len(s.metrics) >= s.maxEntries {
				s.removeOldestLocked()
			}
		}
		metric = &smartMetric{
			Network:   key.Network,
			Site:      key.Site,
			Candidate: key.Candidate,
			Transport: key.Transport,
		}
		s.metrics[key] = metric
	}
	return metric
}

func (s *smartStore) removeOldestLocked() {
	var (
		oldestKey smartMetricKey
		oldest    time.Time
		loaded    bool
	)
	for key, metric := range s.metrics {
		if !loaded || metric.LastUpdated.Before(oldest) {
			oldestKey = key
			oldest = metric.LastUpdated
			loaded = true
		}
	}
	if loaded {
		delete(s.metrics, oldestKey)
	}
}

func (s *smartStore) observeDial(now time.Time, network, site, candidate, transport string, success bool, elapsed time.Duration) {
	s.access.Lock()
	defer s.access.Unlock()
	globalWeight := 1.0
	if !success && site != "" {
		globalWeight = 0.25
	}
	s.observeDialLocked(now, smartMetricKey{Network: network, Candidate: candidate, Transport: transport}, success, elapsed, globalWeight, site == "")
	if site != "" {
		s.observeDialLocked(now, smartMetricKey{Network: network, Site: site, Candidate: candidate, Transport: transport}, success, elapsed, 1, true)
	}
}

func (s *smartStore) observeDialLocked(now time.Time, key smartMetricKey, success bool, elapsed time.Duration, weight float64, updateBreaker bool) {
	metric := s.metric(key, now)
	metric.decay(now, s.halfLife)
	if success {
		metric.Successes += weight
		metric.ConsecutiveFailures = 0
		metric.CircuitUntil = time.Time{}
		if elapsed > 0 {
			metric.updateConnect(float64(elapsed.Microseconds()) / 1000)
		}
	} else {
		metric.Failures += weight
		if updateBreaker {
			metric.ConsecutiveFailures++
			if metric.ConsecutiveFailures >= s.breakerFailures {
				exponent := min(metric.ConsecutiveFailures-s.breakerFailures, 4)
				metric.CircuitUntil = now.Add(s.breakerCooldown * time.Duration(1<<exponent))
			}
		}
	}
	metric.LastUpdated = now
}

func (s *smartStore) observeFirstByte(now time.Time, network, site, candidate, transport string, elapsed time.Duration) {
	if elapsed <= 0 {
		return
	}
	s.access.Lock()
	defer s.access.Unlock()
	s.observeFirstByteLocked(now, smartMetricKey{Network: network, Candidate: candidate, Transport: transport}, elapsed)
	if site != "" {
		s.observeFirstByteLocked(now, smartMetricKey{Network: network, Site: site, Candidate: candidate, Transport: transport}, elapsed)
	}
}

func (s *smartStore) observeFirstByteLocked(now time.Time, key smartMetricKey, elapsed time.Duration) {
	metric := s.metric(key, now)
	metric.decay(now, s.halfLife)
	metric.updateFirstByte(float64(elapsed.Microseconds()) / 1000)
	metric.LastUpdated = now
}

func (s *smartStore) observeThroughput(now time.Time, network, site, candidate, transport string, bytes int64, elapsed time.Duration) {
	if bytes < 64*1024 || elapsed < time.Second {
		return
	}
	bps := float64(bytes) / elapsed.Seconds()
	if bps <= 0 {
		return
	}
	s.access.Lock()
	defer s.access.Unlock()
	s.observeThroughputLocked(now, smartMetricKey{Network: network, Candidate: candidate, Transport: transport}, bps)
	if site != "" {
		s.observeThroughputLocked(now, smartMetricKey{Network: network, Site: site, Candidate: candidate, Transport: transport}, bps)
	}
}

func (s *smartStore) observeThroughputLocked(now time.Time, key smartMetricKey, bps float64) {
	metric := s.metric(key, now)
	metric.decay(now, s.halfLife)
	value := math.Log1p(bps)
	metric.ThroughputLog = updateEWMA(metric.ThroughputLog, value, metric.ThroughputSamples)
	metric.ThroughputSamples++
	metric.LastUpdated = now
}

func (s *smartStore) estimate(now time.Time, network, site, candidate, transport string, minSamples int) smartEstimate {
	s.access.RLock()
	defer s.access.RUnlock()
	global := s.metricCopy(smartMetricKey{Network: network, Candidate: candidate, Transport: transport}, now)
	local := s.metricCopy(smartMetricKey{Network: network, Site: site, Candidate: candidate, Transport: transport}, now)
	return blendSmartEstimate(global, local, minSamples, now)
}

func (s *smartStore) metricCopy(key smartMetricKey, now time.Time) *smartMetric {
	metric := s.metrics[key]
	if metric == nil {
		return nil
	}
	copyMetric := *metric
	copyMetric.decay(now, s.halfLife)
	return &copyMetric
}

func (s *smartStore) snapshot(now time.Time, retention time.Duration, maxEntries int) smartStoreSnapshot {
	s.access.Lock()
	s.pruneLocked(now, retention, maxEntries)
	metrics := make([]smartMetric, 0, len(s.metrics))
	for _, metric := range s.metrics {
		copyMetric := *metric
		copyMetric.decay(now, s.halfLife)
		metrics = append(metrics, copyMetric)
	}
	s.access.Unlock()
	sort.Slice(metrics, func(i, j int) bool {
		return metrics[i].LastUpdated.After(metrics[j].LastUpdated)
	})
	if maxEntries > 0 && len(metrics) > maxEntries {
		metrics = metrics[:maxEntries]
	}
	return smartStoreSnapshot{Version: smartStateVersion, Metrics: metrics}
}

func (s *smartStore) pruneLocked(now time.Time, retention time.Duration, maxEntries int) {
	if retention > 0 {
		for key, metric := range s.metrics {
			if !metric.LastUpdated.IsZero() && now.Sub(metric.LastUpdated) > retention {
				delete(s.metrics, key)
			}
		}
	}
	if maxEntries <= 0 || len(s.metrics) <= maxEntries {
		return
	}
	type metricAge struct {
		key       smartMetricKey
		updatedAt time.Time
	}
	ages := make([]metricAge, 0, len(s.metrics))
	for key, metric := range s.metrics {
		ages = append(ages, metricAge{key: key, updatedAt: metric.LastUpdated})
	}
	sort.Slice(ages, func(i, j int) bool {
		return ages[i].updatedAt.After(ages[j].updatedAt)
	})
	for _, entry := range ages[maxEntries:] {
		delete(s.metrics, entry.key)
	}
}

func (s *smartStore) restore(snapshot smartStoreSnapshot) {
	if snapshot.Version != smartStateVersion {
		return
	}
	s.access.Lock()
	defer s.access.Unlock()
	for index := range snapshot.Metrics {
		metric := snapshot.Metrics[index]
		key := smartMetricKey{
			Network:   metric.Network,
			Site:      metric.Site,
			Candidate: metric.Candidate,
			Transport: metric.Transport,
		}
		copyMetric := metric
		s.metrics[key] = &copyMetric
	}
	s.pruneLocked(time.Now(), s.retention, s.maxEntries)
}

func (m *smartMetric) decay(now time.Time, halfLife time.Duration) {
	if m.LastUpdated.IsZero() || !now.After(m.LastUpdated) || halfLife <= 0 {
		return
	}
	factor := math.Exp(-math.Ln2 * now.Sub(m.LastUpdated).Seconds() / halfLife.Seconds())
	m.Successes *= factor
	m.Failures *= factor
	m.ConnectSamples *= factor
	m.FirstByteSamples *= factor
	m.ThroughputSamples *= factor
}

func (m *smartMetric) updateConnect(value float64) {
	if m.ConnectSamples == 0 {
		m.ConnectMS = value
		m.JitterMS = 0
	} else {
		deviation := math.Abs(value - m.ConnectMS)
		m.ConnectMS = updateEWMA(m.ConnectMS, value, m.ConnectSamples)
		m.JitterMS = updateEWMA(m.JitterMS, deviation, m.ConnectSamples)
	}
	m.ConnectSamples++
}

func (m *smartMetric) updateFirstByte(value float64) {
	m.FirstByteMS = updateEWMA(m.FirstByteMS, value, m.FirstByteSamples)
	m.FirstByteSamples++
}

func updateEWMA(current, value, samples float64) float64 {
	if samples <= 0 {
		return value
	}
	alpha := 2.0 / (math.Min(samples, 9) + 2)
	return current + alpha*(value-current)
}

func blendSmartEstimate(global, local *smartMetric, minSamples int, now time.Time) smartEstimate {
	if minSamples <= 0 {
		minSamples = 3
	}
	if global == nil && local == nil {
		return smartEstimate{Reliability: 0.13, State: "unknown"}
	}
	globalEstimate := estimateMetric(global, now, minSamples)
	if local == nil || local.Site == "" {
		return globalEstimate
	}
	localEstimate := estimateMetric(local, now, minSamples)
	localWeight := math.Min(0.85, localEstimate.Samples/float64(minSamples)*0.85)
	if global == nil {
		localWeight = 1
	}
	return smartEstimate{
		Reliability:            blendValue(globalEstimate.Reliability, localEstimate.Reliability, localWeight),
		ConnectMS:              blendOptional(globalEstimate.ConnectMS, localEstimate.ConnectMS, globalEstimate.HasConnect, localEstimate.HasConnect, localWeight),
		FirstByteMS:            blendOptional(globalEstimate.FirstByteMS, localEstimate.FirstByteMS, globalEstimate.HasFirstByte, localEstimate.HasFirstByte, localWeight),
		ThroughputBPS:          blendOptional(globalEstimate.ThroughputBPS, localEstimate.ThroughputBPS, globalEstimate.HasThroughput, localEstimate.HasThroughput, localWeight),
		ThroughputSamples:      math.Max(globalEstimate.ThroughputSamples, localEstimate.ThroughputSamples),
		LocalThroughputSamples: localEstimate.ThroughputSamples,
		JitterMS:               blendOptional(globalEstimate.JitterMS, localEstimate.JitterMS, globalEstimate.HasConnect, localEstimate.HasConnect, localWeight),
		Samples:                math.Max(globalEstimate.Samples, localEstimate.Samples),
		State:                  strongerState(globalEstimate.State, localEstimate.State),
		CircuitUntil:           laterTime(globalEstimate.CircuitUntil, localEstimate.CircuitUntil),
		LastUpdated:            laterTime(globalEstimate.LastUpdated, localEstimate.LastUpdated),
		HasConnect:             globalEstimate.HasConnect || localEstimate.HasConnect,
		HasFirstByte:           globalEstimate.HasFirstByte || localEstimate.HasFirstByte,
		HasThroughput:          globalEstimate.HasThroughput || localEstimate.HasThroughput,
	}
}

func estimateMetric(metric *smartMetric, now time.Time, minSamples int) smartEstimate {
	if metric == nil {
		return smartEstimate{Reliability: 0.13, State: "unknown"}
	}
	alpha := 1 + metric.Successes
	beta := 1 + metric.Failures
	mean := alpha / (alpha + beta)
	variance := alpha * beta / (math.Pow(alpha+beta, 2) * (alpha + beta + 1))
	reliability := math.Max(0, mean-1.28*math.Sqrt(variance))
	samples := metric.Successes + metric.Failures
	state := "healthy"
	if metric.CircuitUntil.After(now) {
		state = "open"
	} else if !metric.CircuitUntil.IsZero() {
		state = "half_open"
	} else if samples < float64(minSamples) {
		state = "warming"
	} else if reliability < 0.65 {
		state = "suspect"
	}
	return smartEstimate{
		Reliability:       reliability,
		ConnectMS:         metric.ConnectMS,
		FirstByteMS:       metric.FirstByteMS,
		ThroughputBPS:     math.Expm1(metric.ThroughputLog),
		ThroughputSamples: metric.ThroughputSamples,
		JitterMS:          metric.JitterMS,
		Samples:           samples,
		State:             state,
		CircuitUntil:      metric.CircuitUntil,
		LastUpdated:       metric.LastUpdated,
		HasConnect:        metric.ConnectSamples > 0,
		HasFirstByte:      metric.FirstByteSamples > 0,
		HasThroughput:     metric.ThroughputSamples > 0,
	}
}

type smartTrafficProfile uint8

const (
	smartProfileInteractive smartTrafficProfile = iota
	smartProfileBulk
	smartProfileUDP
)

func detectSmartTrafficProfile(transport string, estimates map[string]smartEstimate) smartTrafficProfile {
	if transport == "udp" {
		return smartProfileUDP
	}
	for _, estimate := range estimates {
		if estimate.ThroughputSamples >= 2 {
			return smartProfileBulk
		}
	}
	return smartProfileInteractive
}

func (p smartTrafficProfile) String() string {
	switch p {
	case smartProfileBulk:
		return "bulk"
	case smartProfileUDP:
		return "udp"
	default:
		return "interactive"
	}
}

func smartScore(estimate smartEstimate, exploration, totalSamples float64) float64 {
	return smartScoreForProfile(estimate, smartProfileInteractive, exploration, totalSamples)
}

func smartScoreForProfile(estimate smartEstimate, profile smartTrafficProfile, exploration, totalSamples float64) float64 {
	if estimate.State == "open" {
		return 100
	}
	var reliabilityWeight, connectWeight, firstByteWeight, throughputWeight, jitterWeight float64
	switch profile {
	case smartProfileBulk:
		reliabilityWeight, connectWeight, firstByteWeight, throughputWeight, jitterWeight = 0.35, 0.15, 0.10, 0.35, 0.05
	case smartProfileUDP:
		reliabilityWeight, connectWeight, firstByteWeight, throughputWeight, jitterWeight = 0.55, 0.20, 0, 0, 0.25
	default:
		reliabilityWeight, connectWeight, firstByteWeight, throughputWeight, jitterWeight = 0.45, 0.30, 0.15, 0, 0.10
	}
	connectCost := 0.50
	if estimate.HasConnect {
		connectCost = normalizedLogCost(estimate.ConnectMS, 5000)
	}
	firstByteCost := 0.50
	if estimate.HasFirstByte {
		firstByteCost = normalizedLogCost(estimate.FirstByteMS, 10000)
	}
	throughputCost := 0.60
	if estimate.HasThroughput {
		speedUtility := math.Min(1, math.Log1p(estimate.ThroughputBPS)/math.Log1p(64*1024*1024))
		throughputCost = 1 - speedUtility
	}
	jitterCost := 0.50
	if estimate.HasConnect {
		jitterCost = math.Min(1, estimate.JitterMS/1000)
	}
	score := reliabilityWeight*(1-estimate.Reliability) +
		connectWeight*connectCost +
		firstByteWeight*firstByteCost +
		throughputWeight*throughputCost +
		jitterWeight*jitterCost
	if estimate.State == "half_open" {
		score += 0.20
	}
	if exploration > 0 {
		score -= exploration * math.Sqrt(math.Log(totalSamples+2)/(estimate.Samples+1))
	}
	return math.Max(0, score)
}

func normalizedLogCost(value, ceiling float64) float64 {
	if value <= 0 {
		return 0
	}
	return math.Min(1, math.Log1p(value)/math.Log1p(ceiling))
}

func blendValue(global, local, localWeight float64) float64 {
	return global*(1-localWeight) + local*localWeight
}

func blendOptional(global, local float64, hasGlobal, hasLocal bool, localWeight float64) float64 {
	switch {
	case hasGlobal && hasLocal:
		return blendValue(global, local, localWeight)
	case hasLocal:
		return local
	default:
		return global
	}
}

func strongerState(global, local string) string {
	priority := map[string]int{
		"unknown":   0,
		"healthy":   1,
		"warming":   2,
		"suspect":   3,
		"half_open": 4,
		"open":      5,
	}
	if priority[local] > priority[global] {
		return local
	}
	return global
}

func laterTime(left, right time.Time) time.Time {
	if right.After(left) {
		return right
	}
	return left
}
