package group

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash/fnv"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"

	"golang.org/x/net/publicsuffix"
)

const (
	defaultSmartProbeInterval     = 10 * time.Minute
	defaultSmartProbeCycleTimeout = 30 * time.Second
	defaultSmartProbeTimeout      = 5 * time.Second
	defaultSmartAttemptTimeout    = 4 * time.Second
	defaultSmartSiteStickiness    = 10 * time.Minute
	defaultSmartHedgeDelay        = 450 * time.Millisecond
	minSmartHedgeDelay            = 250 * time.Millisecond
	maxSmartHedgeDelay            = 750 * time.Millisecond
	defaultSmartSwitchMargin      = 0.08
	defaultSmartExploration       = 0.08
	defaultSmartMinSamples        = 3
	defaultSmartMaxAttempts       = 3
	defaultSmartBreakerFailures   = 3
	defaultSmartBreakerCooldown   = 2 * time.Minute
	defaultSmartHalfLife          = 30 * time.Minute
	defaultSmartHistoryRetention  = 7 * 24 * time.Hour
	defaultSmartMaxHistoryEntries = 50000
	smartStatusCandidateLimit     = 32
	smartNetworkFingerprintTTL    = 2 * time.Second
)

func RegisterSmart(registry *outbound.Registry) {
	outbound.Register[option.SmartOutboundOptions](registry, C.TypeSmart, NewSmart)
}

var _ adapter.SmartGroup = (*Smart)(nil)

var errSmartNoCandidates = errors.New("smart group has no leaf candidates")

type smartAffinity struct {
	Candidate string
	ExpiresAt time.Time
}

type smartRank struct {
	outbound adapter.Outbound
	status   adapter.SmartCandidateStatus
	profile  smartTrafficProfile
	estimate smartEstimate
	eligible bool
}

type smartRanking struct {
	ranks           []smartRank
	candidates      []adapter.Outbound
	rankBuffer      *[]smartRank
	candidateBuffer *[]adapter.Outbound
}

type smartDialAttempt struct {
	rankIndex    int
	attemptIndex int
	rank         smartRank
	candidate    adapter.Outbound
	reserved     bool
}

type smartDialResult struct {
	attempt smartDialAttempt
	conn    net.Conn
	err     error
	elapsed time.Duration
}

var smartRankPool = sync.Pool{New: func() any {
	buffer := make([]smartRank, 0, 64)
	return &buffer
}}

var smartCandidatePool = sync.Pool{New: func() any {
	buffer := make([]adapter.Outbound, 0, 64)
	return &buffer
}}

func acquireSmartRanking(candidateCount int) *smartRanking {
	rankBuffer := smartRankPool.Get().(*[]smartRank)
	ranks := *rankBuffer
	if cap(ranks) < candidateCount {
		ranks = make([]smartRank, 0, candidateCount)
	}
	candidateBuffer := smartCandidatePool.Get().(*[]adapter.Outbound)
	candidates := *candidateBuffer
	if cap(candidates) < candidateCount {
		candidates = make([]adapter.Outbound, 0, candidateCount)
	}
	return &smartRanking{
		ranks:           ranks[:0],
		candidates:      candidates[:0],
		rankBuffer:      rankBuffer,
		candidateBuffer: candidateBuffer,
	}
}

func (r *smartRanking) Release() {
	if r == nil {
		return
	}
	clear(r.ranks)
	clear(r.candidates)
	if cap(r.ranks) <= 4096 {
		*r.rankBuffer = r.ranks[:0]
		smartRankPool.Put(r.rankBuffer)
	}
	if cap(r.candidates) <= 4096 {
		*r.candidateBuffer = r.candidates[:0]
		smartCandidatePool.Put(r.candidateBuffer)
	}
	r.ranks = nil
	r.candidates = nil
	r.rankBuffer = nil
	r.candidateBuffer = nil
}

type smartFingerprintCache struct {
	value     string
	expiresAt int64
}

type smartControlState struct {
	access          sync.Mutex
	pinned          string
	temporary       string
	temporaryUntil  time.Time
	temporaryReason string
}

type Smart struct {
	outbound.Adapter
	ctx        context.Context
	outbound   adapter.OutboundManager
	connection adapter.ConnectionManager
	network    adapter.NetworkManager
	logger     log.ContextLogger
	tags       []string

	provider        adapter.ProviderManager
	providerAccess  sync.Mutex
	providers       map[string]adapter.Provider
	providerHandles map[string]*list.Element[adapter.ProviderUpdateCallback]
	outboundsCache  map[string][]adapter.Outbound
	providerTags    []string
	exclude         *regexp.Regexp
	include         *regexp.Regexp
	useAllProviders bool

	access          sync.RWMutex
	candidates      []adapter.Outbound
	candidateByTag  map[string]adapter.Outbound
	control         *smartControlState
	lastSelected    map[string]string
	affinity        map[string]smartAffinity
	halfOpen        map[string]struct{}
	latest          common.TypedValue[adapter.Outbound]
	fingerprint     atomic.Pointer[smartFingerprintCache]
	fingerprintLock sync.Mutex

	statusAccess sync.RWMutex
	status       adapter.SmartGroupStatus
	reachAccess  sync.RWMutex
	reachTests   []smartReachTest
	reachResults map[string]map[string]adapter.SmartReachCandidateStatus
	reachLastRun map[string]time.Time
	reachForce   atomic.Bool

	store             *smartStore
	probeURL          string
	probeInterval     time.Duration
	probeCycleTimeout time.Duration
	probeTimeout      time.Duration
	maxAttempts       int
	attemptTimeout    time.Duration
	siteStickiness    time.Duration
	switchMargin      float64
	exploration       float64
	minSamples        int
	halfLife          time.Duration
	breakerFailures   int
	breakerCooldown   time.Duration
	historyPath       string
	historyRetention  time.Duration
	maxHistoryEntries int
	interruptGroup    *interrupt.Group
	interruptExternal bool
	probing           atomic.Bool
	probeCursor       atomic.Uint64
	closing           atomic.Bool
	cancel            context.CancelFunc
	worker            sync.WaitGroup
	lifecycleAccess   sync.Mutex
	published         bool
	postStarted       bool
	retired           bool
	workerStarted     bool
	historyEntry      *smartHistoryEntry
	historyReleased   bool
	loadedHistory     map[string]smartStoreSnapshot
}

var _ adapter.RuntimeEpochLifecycle = (*Smart)(nil)

type smartHistoryEntry struct {
	fileAccess sync.Mutex
	stores     map[string]smartHistoryStore
	controls   map[string]*smartControlState
	references map[string]int
	persisted  map[string]smartStoreSnapshot
}

type smartHistoryStore struct {
	store      *smartStore
	retention  time.Duration
	maxEntries int
}

const smartHistoryFileVersion = 2

type smartHistoryFile struct {
	Version int                           `json:"version"`
	Groups  map[string]smartStoreSnapshot `json:"groups"`
}

var smartHistoryPool = struct {
	sync.Mutex
	entries map[string]*smartHistoryEntry
}{
	entries: make(map[string]*smartHistoryEntry),
}

func NewSmart(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SmartOutboundOptions) (adapter.Outbound, error) {
	reachTests, err := buildSmartReachTests(options.ReachTests)
	if err != nil {
		return nil, err
	}
	probeInterval := time.Duration(options.ProbeInterval)
	if probeInterval <= 0 {
		probeInterval = defaultSmartProbeInterval
	}
	probeCycleTimeout := time.Duration(options.ProbeCycleTimeout)
	if probeCycleTimeout <= 0 {
		probeCycleTimeout = defaultSmartProbeCycleTimeout
	}
	probeTimeout := time.Duration(options.ProbeTimeout)
	if probeTimeout <= 0 {
		probeTimeout = defaultSmartProbeTimeout
	}
	if probeCycleTimeout < probeTimeout {
		probeCycleTimeout = probeTimeout
	}
	maxAttempts := options.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = defaultSmartMaxAttempts
	}
	attemptTimeout := time.Duration(options.AttemptTimeout)
	if attemptTimeout <= 0 {
		attemptTimeout = defaultSmartAttemptTimeout
	}
	siteStickiness := time.Duration(options.SiteStickiness)
	if siteStickiness <= 0 {
		siteStickiness = defaultSmartSiteStickiness
	}
	switchMargin := defaultSmartSwitchMargin
	if options.SwitchMargin != nil {
		switchMargin = max(0, *options.SwitchMargin)
	}
	exploration := defaultSmartExploration
	if options.Exploration != nil {
		exploration = max(0, *options.Exploration)
	}
	minSamples := options.MinSamples
	if minSamples <= 0 {
		minSamples = defaultSmartMinSamples
	}
	breakerFailures := options.BreakerFailures
	if breakerFailures <= 0 {
		breakerFailures = defaultSmartBreakerFailures
	}
	breakerCooldown := time.Duration(options.BreakerCooldown)
	if breakerCooldown <= 0 {
		breakerCooldown = defaultSmartBreakerCooldown
	}
	halfLife := time.Duration(options.HalfLife)
	if halfLife <= 0 {
		halfLife = defaultSmartHalfLife
	}
	historyRetention := time.Duration(options.HistoryRetention)
	if historyRetention <= 0 {
		historyRetention = defaultSmartHistoryRetention
	}
	maxHistoryEntries := options.MaxHistoryEntries
	if maxHistoryEntries <= 0 {
		maxHistoryEntries = defaultSmartMaxHistoryEntries
	}
	historyPath := options.HistoryPath
	if historyPath == "" {
		historyPath = "smart-history-" + safeSmartFileName(tag) + ".json"
	}
	store := newSmartStore(halfLife, breakerFailures, breakerCooldown)
	store.setBounds(historyRetention, maxHistoryEntries)
	smart := &Smart{
		Adapter:    outbound.NewAdapter(C.TypeSmart, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.Outbounds),
		ctx:        ctx,
		outbound:   service.FromContext[adapter.OutboundManager](ctx),
		connection: service.FromContext[adapter.ConnectionManager](ctx),
		network:    service.FromContext[adapter.NetworkManager](ctx),
		logger:     logger,
		tags:       options.Outbounds,

		provider:        service.FromContext[adapter.ProviderManager](ctx),
		providers:       make(map[string]adapter.Provider),
		providerHandles: make(map[string]*list.Element[adapter.ProviderUpdateCallback]),
		outboundsCache:  make(map[string][]adapter.Outbound),
		providerTags:    options.Providers,
		exclude:         (*regexp.Regexp)(options.Exclude),
		include:         (*regexp.Regexp)(options.Include),
		useAllProviders: options.UseAllProviders,

		candidateByTag: make(map[string]adapter.Outbound),
		control:        &smartControlState{},
		lastSelected:   make(map[string]string),
		affinity:       make(map[string]smartAffinity),
		halfOpen:       make(map[string]struct{}),
		store:          store,

		probeURL:          options.URL,
		probeInterval:     probeInterval,
		probeCycleTimeout: probeCycleTimeout,
		probeTimeout:      probeTimeout,
		maxAttempts:       maxAttempts,
		attemptTimeout:    attemptTimeout,
		siteStickiness:    siteStickiness,
		switchMargin:      switchMargin,
		exploration:       exploration,
		minSamples:        minSamples,
		halfLife:          halfLife,
		breakerFailures:   breakerFailures,
		breakerCooldown:   breakerCooldown,
		historyPath:       filemanager.BasePath(ctx, historyPath),
		historyRetention:  historyRetention,
		maxHistoryEntries: maxHistoryEntries,
		interruptGroup:    interrupt.NewGroup(),
		interruptExternal: options.InterruptConnections,
		reachTests:        reachTests,
		reachResults:      make(map[string]map[string]adapter.SmartReachCandidateStatus),
		reachLastRun:      make(map[string]time.Time),
	}
	return smart, nil
}

func (s *Smart) Start() error {
	if s.providerHandles == nil {
		s.providerHandles = make(map[string]*list.Element[adapter.ProviderUpdateCallback])
	}
	if s.useAllProviders {
		for _, provider := range s.provider.Providers() {
			s.providerTags = append(s.providerTags, provider.Tag())
			s.providers[provider.Tag()] = provider
			s.providerHandles[provider.Tag()] = provider.RegisterCallback(s.onProviderUpdated)
		}
	} else {
		for index, tag := range s.providerTags {
			provider, loaded := s.provider.Get(tag)
			if !loaded {
				return E.New("outbound provider ", index, " not found: ", tag)
			}
			s.providers[tag] = provider
			s.providerHandles[tag] = provider.RegisterCallback(s.onProviderUpdated)
		}
	}
	if len(s.tags)+len(s.providerTags) == 0 {
		return E.New("missing outbound and provider tags")
	}
	if err := s.rebuildCandidates(""); err != nil {
		if !errors.Is(err, errSmartNoCandidates) || len(s.providerTags) == 0 {
			return err
		}
		s.setWarmingStatus("waiting for provider candidates")
		if s.logger != nil {
			s.logger.Info("smart group waiting for provider candidates")
		}
	}
	if cacheFile := service.FromContext[adapter.CacheFile](s.ctx); cacheFile != nil {
		pinned := cacheFile.LoadSelected(s.Tag())
		if pinned != "" {
			s.SelectOutbound(pinned)
		}
	}
	return nil
}

func (s *Smart) PostStart() error {
	s.lifecycleAccess.Lock()
	s.postStarted = true
	s.startWorkerLocked()
	s.lifecycleAccess.Unlock()
	return nil
}

func (s *Smart) OnRuntimeEpochPublish() error {
	return nil
}

func (s *Smart) OnRuntimeEpochPublishCommit() {
	s.lifecycleAccess.Lock()
	s.publishHistoryLocked()
	s.startWorkerLocked()
	s.lifecycleAccess.Unlock()
}

func (s *Smart) OnRuntimeEpochPublishRollback() { s.OnRuntimeEpochRetire() }

func (s *Smart) OnRuntimeEpochRetire() {
	s.stopWorker()
}

func (s *Smart) publishHistoryLocked() {
	if s.published {
		return
	}
	smartHistoryPool.Lock()
	entry := smartHistoryPool.entries[s.historyPath]
	if entry == nil {
		entry = &smartHistoryEntry{
			stores:     make(map[string]smartHistoryStore),
			controls:   make(map[string]*smartControlState),
			references: make(map[string]int),
			persisted:  cloneSmartHistorySnapshots(s.loadedHistory),
		}
		smartHistoryPool.entries[s.historyPath] = entry
	} else if len(s.loadedHistory) > 0 {
		for tag, snapshot := range s.loadedHistory {
			if _, loaded := entry.persisted[tag]; !loaded {
				entry.persisted[tag] = snapshot
			}
		}
	}
	if historyStore, loaded := entry.stores[s.Tag()]; loaded {
		s.store = historyStore.store
	} else {
		entry.stores[s.Tag()] = smartHistoryStore{store: s.store}
	}
	entry.stores[s.Tag()] = smartHistoryStore{
		store:      s.store,
		retention:  s.historyRetention,
		maxEntries: s.maxHistoryEntries,
	}
	control := entry.controls[s.Tag()]
	if control == nil {
		control = s.control
		entry.controls[s.Tag()] = control
	}
	s.control = control
	entry.references[s.Tag()]++
	s.store.setPolicy(s.halfLife, s.breakerFailures, s.breakerCooldown)
	s.store.setBounds(s.historyRetention, s.maxHistoryEntries)
	s.historyEntry = entry
	s.published = true
	smartHistoryPool.Unlock()
}

func (s *Smart) stopWorker() {
	s.lifecycleAccess.Lock()
	s.retired = true
	if s.cancel != nil {
		s.cancel()
	}
	s.lifecycleAccess.Unlock()
}

func (s *Smart) startWorkerLocked() {
	if !s.published || !s.postStarted || s.retired || s.workerStarted {
		return
	}
	workerCtx, cancel := context.WithCancel(s.ctx)
	s.cancel = cancel
	s.workerStarted = true
	s.worker.Add(1)
	go s.run(workerCtx)
}

func (s *Smart) Close() error {
	if !s.closing.CompareAndSwap(false, true) {
		return nil
	}
	s.OnRuntimeEpochRetire()
	s.unregisterProviderCallbacks()
	s.worker.Wait()
	s.lifecycleAccess.Lock()
	published := s.published
	s.lifecycleAccess.Unlock()
	if published {
		s.releaseHistory()
	}
	return nil
}

func (s *Smart) unregisterProviderCallbacks() {
	s.providerAccess.Lock()
	for tag, handle := range s.providerHandles {
		if provider := s.providers[tag]; provider != nil && handle != nil {
			provider.UnregisterCallback(handle)
		}
	}
	clear(s.providerHandles)
	s.providerAccess.Unlock()
}

func (s *Smart) run(ctx context.Context) {
	defer s.worker.Done()
	probeTicker := time.NewTicker(s.probeInterval)
	reachTicker := time.NewTicker(30 * time.Second)
	defer probeTicker.Stop()
	defer reachTicker.Stop()
	probeCtx, cancel := context.WithTimeout(ctx, s.probeCycleTimeout)
	_, _ = s.probe(probeCtx)
	cancel()
	s.runDueReachTests(ctx, true)
	for {
		select {
		case <-ctx.Done():
			return
		case <-probeTicker.C:
			probeCtx, cancel := context.WithTimeout(ctx, s.probeCycleTimeout)
			_, _ = s.probe(probeCtx)
			cancel()
		case <-reachTicker.C:
			s.runDueReachTests(ctx, s.reachForce.Swap(false))
		}
	}
}

func (s *Smart) Network() []string {
	return []string{N.NetworkTCP, N.NetworkUDP}
}

func (s *Smart) Now() string {
	selected := s.latest.Load()
	if selected == nil {
		return ""
	}
	tag := selected.Tag()
	s.access.RLock()
	_, loaded := s.candidateByTag[tag]
	s.access.RUnlock()
	if !loaded {
		return ""
	}
	return tag
}

func (s *Smart) All() []string {
	s.access.RLock()
	defer s.access.RUnlock()
	return common.Map(s.candidates, func(it adapter.Outbound) string { return it.Tag() })
}

func (s *Smart) SmartStatus() adapter.SmartGroupStatus {
	pinned, temporary, expiresAt, reason := s.controlSnapshot(time.Now())
	s.statusAccess.RLock()
	defer s.statusAccess.RUnlock()
	status := s.status
	status.Pinned = pinned
	status.TemporaryOverride = temporary
	status.OverrideReason = reason
	if temporary != "" {
		status.OverrideExpiresAt = &expiresAt
		status.OverrideRemainingSeconds = max(0, int64(time.Until(expiresAt).Seconds()))
	}
	status.Candidates = append([]adapter.SmartCandidateStatus(nil), status.Candidates...)
	status.StateCounts = cloneSmartStateCounts(status.StateCounts)
	status.ReachTests = s.reachTestStatus()
	return status
}

func cloneSmartStateCounts(source map[string]int) map[string]int {
	if source == nil {
		return nil
	}
	result := make(map[string]int, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func (s *Smart) SelectOutbound(tag string) bool {
	s.access.RLock()
	if _, loaded := s.candidateByTag[tag]; !loaded {
		s.access.RUnlock()
		return false
	}
	s.access.RUnlock()
	s.control.access.Lock()
	s.control.pinned = tag
	s.control.access.Unlock()
	if cacheFile := service.FromContext[adapter.CacheFile](s.ctx); cacheFile != nil && s.Tag() != "" {
		if err := cacheFile.StoreSelected(s.Tag(), tag); err != nil {
			s.logger.Error("store smart pin: ", err)
		}
	}
	return true
}

func (s *Smart) ClearSelection() {
	s.control.access.Lock()
	s.control.pinned = ""
	s.control.access.Unlock()
	if cacheFile := service.FromContext[adapter.CacheFile](s.ctx); cacheFile != nil && s.Tag() != "" {
		if err := cacheFile.StoreSelected(s.Tag(), ""); err != nil {
			s.logger.Error("clear smart pin: ", err)
		}
	}
}

func (s *Smart) SelectTemporaryOutbound(tag string, ttl time.Duration, reason string) bool {
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	s.access.RLock()
	if _, loaded := s.candidateByTag[tag]; !loaded {
		s.access.RUnlock()
		return false
	}
	s.access.RUnlock()
	s.control.access.Lock()
	s.control.temporary = tag
	s.control.temporaryUntil = time.Now().Add(ttl)
	s.control.temporaryReason = reason
	s.control.access.Unlock()
	if s.logger != nil {
		s.logger.Info("smart temporary override selected: ", tag, " for ", ttl)
	}
	return true
}

func (s *Smart) ClearTemporarySelection() {
	s.control.access.Lock()
	s.clearTemporaryLocked()
	s.control.access.Unlock()
}

func (s *Smart) clearTemporaryLocked() {
	s.control.temporary = ""
	s.control.temporaryUntil = time.Time{}
	s.control.temporaryReason = ""
}

func (s *Smart) controlSnapshot(now time.Time) (string, string, time.Time, string) {
	s.control.access.Lock()
	if s.control.temporary != "" && !s.control.temporaryUntil.After(now) {
		if s.logger != nil {
			s.logger.Info("smart temporary override expired: ", s.control.temporary)
		}
		s.clearTemporaryLocked()
	}
	pinned := s.control.pinned
	temporary := s.control.temporary
	expiresAt := s.control.temporaryUntil
	reason := s.control.temporaryReason
	s.control.access.Unlock()

	s.access.RLock()
	_, temporaryExists := s.candidateByTag[temporary]
	s.access.RUnlock()
	if temporary == "" || temporaryExists {
		return pinned, temporary, expiresAt, reason
	}

	s.control.access.Lock()
	if temporary != "" && !temporaryExists && s.control.temporary == temporary {
		s.clearTemporaryLocked()
	}
	pinned = s.control.pinned
	temporary = s.control.temporary
	expiresAt = s.control.temporaryUntil
	reason = s.control.temporaryReason
	s.control.access.Unlock()
	return pinned, temporary, expiresAt, reason
}

func (s *Smart) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	transport := N.NetworkName(network)
	ranking, networkKey, siteKey, siteDisplay := s.rankPooled(ctx, transport, destination)
	defer ranking.Release()
	ranks := ranking.ranks
	if len(ranks) == 0 {
		return nil, E.New("smart group is warming: no supported candidate")
	}
	if !hasEligibleSmartRank(ranks) {
		return nil, E.New("smart group has no service-reachable candidate")
	}
	attempts := s.collectDialAttempts(ranks, networkKey, siteKey, transport)
	if len(attempts) == 0 {
		s.updateStatusSelected(networkKey, siteDisplay, transport, ranks, "", "all eligible candidates are circuit-open or recovery-busy")
		return nil, E.New("all smart candidates are circuit-open or recovery-busy")
	}
	if conn, result, attemptErrors, ok := s.dialContextAdaptive(ctx, network, destination, attempts, networkKey, siteKey, transport); ok {
		candidate := result.attempt.candidate
		s.markSelected(candidate, networkKey, siteKey, siteDisplay, transport, ranks, result.attempt.attemptIndex)
		conn = s.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsProviderConnectionFromContext(ctx))
		return newSmartObservedConn(conn, time.Now().Add(-result.elapsed), func(firstByte time.Duration) {
			s.store.observeFirstByte(time.Now(), networkKey, siteKey, candidate.Tag(), transport, firstByte)
		}, func(bytes int64, duration time.Duration) {
			s.store.observeThroughput(time.Now(), networkKey, siteKey, candidate.Tag(), transport, bytes, duration)
		}), nil
	} else {
		s.updateStatusSelected(networkKey, siteDisplay, transport, ranks, "", "all eligible candidates failed")
		if len(attemptErrors) == 0 {
			return nil, E.New("all smart candidates are circuit-open or recovery-busy")
		}
		return nil, errors.Join(attemptErrors...)
	}
}

func (s *Smart) collectDialAttempts(ranks []smartRank, networkKey, siteKey, transport string) []smartDialAttempt {
	maxAttempts := s.maxAttempts
	if maxAttempts <= 0 {
		maxAttempts = defaultSmartMaxAttempts
	}
	attempts := make([]smartDialAttempt, 0, min(maxAttempts, len(ranks)))
	for rankIndex := range ranks {
		if len(attempts) >= maxAttempts {
			break
		}
		rank := ranks[rankIndex]
		if !rank.eligible || rank.status.State == "open" {
			continue
		}
		reserved := s.reserveHalfOpen(rank, networkKey, siteKey, transport)
		if rank.status.State == "half_open" && !reserved {
			continue
		}
		candidate := rank.outbound
		attempts = append(attempts, smartDialAttempt{
			rankIndex:    rankIndex,
			attemptIndex: len(attempts),
			rank:         rank,
			candidate:    candidate,
			reserved:     reserved,
		})
	}
	return attempts
}

func (s *Smart) dialContextAdaptive(ctx context.Context, network string, destination M.Socksaddr, attempts []smartDialAttempt, networkKey, siteKey, transport string) (net.Conn, smartDialResult, []error, bool) {
	parentCtx, cancelAll := context.WithCancel(ctx)
	defer cancelAll()
	results := make(chan smartDialResult, len(attempts))
	started := 0
	defer func() {
		for index := started; index < len(attempts); index++ {
			if attempts[index].reserved {
				s.releaseHalfOpen(attempts[index].candidate.Tag(), networkKey, siteKey, transport)
			}
		}
	}()
	startAttempt := func(attempt smartDialAttempt) {
		go func() {
			startedAt := time.Now()
			attemptCtx := parentCtx
			var cancel context.CancelFunc
			if s.attemptTimeout > 0 {
				attemptCtx, cancel = context.WithTimeout(parentCtx, s.attemptTimeout)
			}
			conn, err := attempt.candidate.DialContext(attemptCtx, network, destination)
			if cancel != nil {
				cancel()
			}
			if attempt.reserved {
				s.releaseHalfOpen(attempt.candidate.Tag(), networkKey, siteKey, transport)
			}
			elapsed := time.Since(startedAt)
			if err == nil && parentCtx.Err() != nil {
				conn.Close()
				return
			}
			results <- smartDialResult{attempt: attempt, conn: conn, err: err, elapsed: elapsed}
		}()
	}

	active := 0
	startAttempt(attempts[started])
	started++
	active++

	var hedgeTimer *time.Timer
	var hedgeC <-chan time.Time
	resetHedge := func() {
		if started >= len(attempts) || active == 0 {
			if hedgeTimer != nil {
				hedgeTimer.Stop()
			}
			hedgeC = nil
			return
		}
		delay := s.smartHedgeDelay()
		if delay <= 0 {
			hedgeC = nil
			return
		}
		if hedgeTimer == nil {
			hedgeTimer = time.NewTimer(delay)
		} else {
			if !hedgeTimer.Stop() {
				select {
				case <-hedgeTimer.C:
				default:
				}
			}
			hedgeTimer.Reset(delay)
		}
		hedgeC = hedgeTimer.C
	}
	stopHedge := func() {
		if hedgeTimer != nil {
			hedgeTimer.Stop()
		}
	}
	defer stopHedge()
	resetHedge()

	var attemptErrors []error
	for active > 0 {
		select {
		case <-ctx.Done():
			return nil, smartDialResult{}, append(attemptErrors, ctx.Err()), false
		case <-hedgeC:
			if started < len(attempts) {
				startAttempt(attempts[started])
				started++
				active++
			}
			resetHedge()
		case result := <-results:
			active--
			candidate := result.attempt.candidate
			if result.err != nil {
				s.store.observeDial(time.Now(), networkKey, siteKey, candidate.Tag(), transport, false, result.elapsed)
				s.clearBrokenPin(candidate.Tag(), networkKey, siteKey, transport)
				attemptErrors = append(attemptErrors, E.Cause(result.err, "smart candidate ", candidate.Tag()))
				if started < len(attempts) {
					startAttempt(attempts[started])
					started++
					active++
				}
				resetHedge()
				continue
			}
			s.store.observeDial(time.Now(), networkKey, siteKey, candidate.Tag(), transport, true, result.elapsed)
			cancelAll()
			return result.conn, result, attemptErrors, true
		}
	}
	return nil, smartDialResult{}, attemptErrors, false
}

func (s *Smart) smartHedgeDelay() time.Duration {
	if s.maxAttempts <= 1 {
		return 0
	}
	if s.attemptTimeout <= 0 {
		return defaultSmartHedgeDelay
	}
	delay := s.attemptTimeout / 3
	if delay < minSmartHedgeDelay {
		return minSmartHedgeDelay
	}
	if delay > maxSmartHedgeDelay {
		return maxSmartHedgeDelay
	}
	return delay
}

func (s *Smart) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	transport := N.NetworkUDP
	ranking, networkKey, siteKey, siteDisplay := s.rankPooled(ctx, transport, destination)
	defer ranking.Release()
	ranks := ranking.ranks
	if len(ranks) == 0 {
		return nil, E.New("smart group is warming: no supported candidate")
	}
	if !hasEligibleSmartRank(ranks) {
		return nil, E.New("smart group has no service-reachable UDP candidate")
	}
	var attemptErrors []error
	attemptCount := 0
	for rankIndex := range ranks {
		rank := ranks[rankIndex]
		if !rank.eligible || rank.status.State == "open" || attemptCount >= s.maxAttempts {
			continue
		}
		reserved := s.reserveHalfOpen(rank, networkKey, siteKey, transport)
		if rank.status.State == "half_open" && !reserved {
			continue
		}
		candidate := rank.outbound
		attemptIndex := attemptCount
		attemptCount++
		startedAt := time.Now()
		attemptCtx := ctx
		var cancel context.CancelFunc
		if s.attemptTimeout > 0 {
			attemptCtx, cancel = context.WithTimeout(ctx, s.attemptTimeout)
		}
		conn, err := candidate.ListenPacket(attemptCtx, destination)
		if cancel != nil {
			cancel()
		}
		if reserved {
			s.releaseHalfOpen(candidate.Tag(), networkKey, siteKey, transport)
		}
		elapsed := time.Since(startedAt)
		if err != nil {
			s.store.observeDial(time.Now(), networkKey, siteKey, candidate.Tag(), transport, false, elapsed)
			s.clearBrokenPin(candidate.Tag(), networkKey, siteKey, transport)
			attemptErrors = append(attemptErrors, E.Cause(err, "smart candidate ", candidate.Tag()))
			continue
		}
		s.store.observeDial(time.Now(), networkKey, siteKey, candidate.Tag(), transport, true, elapsed)
		s.markSelected(candidate, networkKey, siteKey, siteDisplay, transport, ranks, attemptIndex)
		return s.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsProviderConnectionFromContext(ctx)), nil
	}
	s.updateStatusSelected(networkKey, siteDisplay, transport, ranks, "", "all eligible UDP candidates failed")
	if len(attemptErrors) == 0 {
		return nil, E.New("all smart UDP candidates are circuit-open or recovery-busy")
	}
	return nil, errors.Join(attemptErrors...)
}

func (s *Smart) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	s.connection.NewConnection(ctx, s, conn, metadata, onClose)
}

func (s *Smart) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	s.connection.NewPacketConnection(ctx, s, conn, metadata, onClose)
}

func hasEligibleSmartRank(ranks []smartRank) bool {
	for _, rank := range ranks {
		if rank.eligible && rank.status.State != "open" {
			return true
		}
	}
	return false
}

func (s *Smart) URLTest(ctx context.Context) (map[string]uint16, error) {
	return s.probe(ctx)
}

func (s *Smart) probe(ctx context.Context) (map[string]uint16, error) {
	result := make(map[string]uint16)
	if s.probing.Swap(true) {
		return result, nil
	}
	defer s.probing.Store(false)
	s.access.RLock()
	candidates := append([]adapter.Outbound(nil), s.candidates...)
	s.access.RUnlock()
	if len(candidates) > 1 {
		start := int(s.probeCursor.Add(1)-1) % len(candidates)
		candidates = append(candidates[start:], candidates[:start]...)
	}
	type probeResult struct {
		candidate adapter.Outbound
		delay     uint16
		err       error
		penalize  bool
	}
	results := make(chan probeResult, len(candidates))
	jobs := make(chan adapter.Outbound)
	var waitGroup sync.WaitGroup
	workerCount := min(5, len(candidates))
	for range workerCount {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for candidate := range jobs {
				testCtx, cancel := context.WithTimeout(ctx, s.probeTimeout)
				delay, err := urltest.URLTest(testCtx, s.probeURL, candidate)
				penalize := err != nil && ctx.Err() == nil
				cancel()
				results <- probeResult{candidate: candidate, delay: delay, err: err, penalize: penalize}
			}
		}()
	}
	dispatching := true
	for _, candidate := range candidates {
		if common.Contains(candidate.Network(), N.NetworkTCP) {
			select {
			case jobs <- candidate:
			case <-ctx.Done():
				dispatching = false
			}
			if !dispatching {
				break
			}
		}
	}
	close(jobs)
	waitGroup.Wait()
	close(results)
	collected := make([]probeResult, 0, len(candidates))
	successes := 0
	for probe := range results {
		collected = append(collected, probe)
		if probe.err == nil {
			successes++
			result[probe.candidate.Tag()] = probe.delay
		}
	}
	networkKey := s.networkFingerprint()
	commonFailure := len(collected) > 1 && successes == 0
	for _, probe := range collected {
		if probe.err == nil {
			s.store.observeDial(time.Now(), networkKey, "", probe.candidate.Tag(), N.NetworkTCP, true, time.Duration(probe.delay)*time.Millisecond)
		} else if probe.penalize && !commonFailure {
			s.store.observeDial(time.Now(), networkKey, "", probe.candidate.Tag(), N.NetworkTCP, false, s.probeTimeout)
		}
	}
	if commonFailure {
		if s.logger != nil {
			s.logger.Warn("smart probe suppressed candidate penalties because every candidate failed")
		}
		return result, E.New("all smart probes failed; candidate penalties suppressed")
	}
	return result, nil
}

func (s *Smart) rank(ctx context.Context, transport string, destination M.Socksaddr) ([]smartRank, string, string, string) {
	ranking, networkKey, siteKey, siteDisplay := s.rankPooled(ctx, transport, destination)
	ranks := append([]smartRank(nil), ranking.ranks...)
	ranking.Release()
	return ranks, networkKey, siteKey, siteDisplay
}

func (s *Smart) rankPooled(ctx context.Context, transport string, destination M.Socksaddr) (*smartRanking, string, string, string) {
	now := time.Now()
	pinned, temporary, _, _ := s.controlSnapshot(now)
	networkKey := s.networkFingerprint()
	siteDisplay, siteKey := smartSiteIdentity(adapter.ContextFrom(ctx), destination)
	s.access.RLock()
	ranking := acquireSmartRanking(len(s.candidates))
	ranking.candidates = append(ranking.candidates, s.candidates...)
	lastSelected := s.lastSelected[networkKey+"\x00"+transport]
	affinity := s.affinity[networkKey+"\x00"+siteKey+"\x00"+transport]
	s.access.RUnlock()

	totalSamples := 0.0
	profile := smartProfileInteractive
	if transport == N.NetworkUDP {
		profile = smartProfileUDP
	}
	for _, candidate := range ranking.candidates {
		if !common.Contains(candidate.Network(), transport) {
			continue
		}
		estimate := s.store.estimate(now, networkKey, siteKey, candidate.Tag(), transport, s.minSamples)
		totalSamples += estimate.Samples
		profileThroughputSamples := estimate.ThroughputSamples
		if siteKey != "" {
			profileThroughputSamples = estimate.LocalThroughputSamples
		}
		if profile == smartProfileInteractive && profileThroughputSamples >= 2 {
			profile = smartProfileBulk
		}
		ranking.ranks = append(ranking.ranks, smartRank{
			outbound: candidate,
			estimate: estimate,
			eligible: true,
			status: adapter.SmartCandidateStatus{
				Tag:           candidate.Tag(),
				State:         estimate.State,
				Reliability:   estimate.Reliability,
				ConnectMS:     estimate.ConnectMS,
				FirstByteMS:   estimate.FirstByteMS,
				ThroughputBPS: estimate.ThroughputBPS,
				Samples:       estimate.Samples,
			},
		})
	}
	for index := range ranking.ranks {
		ranking.ranks[index].profile = profile
		ranking.ranks[index].status.Score = smartScoreForProfile(ranking.ranks[index].estimate, profile, s.exploration, totalSamples)
		ranking.ranks[index].status.Reason = smartEstimateReason(ranking.ranks[index].estimate)
		ranking.ranks[index].estimate = smartEstimate{}
	}
	s.applyReachTestEvidence(adapter.ContextFrom(ctx), destination, ranking.ranks)
	sort.SliceStable(ranking.ranks, func(i, j int) bool {
		if ranking.ranks[i].eligible != ranking.ranks[j].eligible {
			return ranking.ranks[i].eligible
		}
		return ranking.ranks[i].status.Score < ranking.ranks[j].status.Score
	})
	ranks := ranking.ranks
	manualPinUnavailable := false
	statusReason := func(reason string) string {
		if manualPinUnavailable {
			return "manual pin unavailable; automatic fallback: " + reason
		}
		return reason
	}
	if len(ranks) == 0 {
		return ranking, networkKey, siteKey, siteDisplay
	}
	if ranks[0].status.State == "open" {
		s.updateStatus(networkKey, siteDisplay, transport, ranks, "no eligible candidates; circuits open")
		return ranking, networkKey, siteKey, siteDisplay
	}
	if temporary != "" {
		if index := smartRankIndex(ranks, temporary); index >= 0 && ranks[index].status.State != "open" {
			ranks[index].eligible = true
			ranks[index].status.Reason = "temporary manual override"
			moveSmartRankFirst(ranks, index)
			s.updateStatus(networkKey, siteDisplay, transport, ranks, "temporary manual override")
			return ranking, networkKey, siteKey, siteDisplay
		}
		s.ClearTemporarySelection()
	}
	if pinned != "" {
		if index := smartRankIndex(ranks, pinned); index >= 0 && ranks[index].status.State != "open" {
			ranks[index].eligible = true
			ranks[index].status.Reason = "manual pin"
			moveSmartRankFirst(ranks, index)
			s.updateStatus(networkKey, siteDisplay, transport, ranks, "manual pin")
			return ranking, networkKey, siteKey, siteDisplay
		}
		manualPinUnavailable = true
	}
	if !hasEligibleSmartRank(ranks) {
		s.updateStatus(networkKey, siteDisplay, transport, ranks, statusReason("no service-reachable candidates"))
		return ranking, networkKey, siteKey, siteDisplay
	}
	bestScore := ranks[0].status.Score
	if affinity.Candidate != "" && affinity.ExpiresAt.After(now) {
		if index := smartRankIndex(ranks, affinity.Candidate); index >= 0 && ranks[index].status.State != "open" && ranks[index].status.Score <= bestScore+s.switchMargin {
			ranks[index].status.Reason = "site affinity within switch margin"
			moveSmartRankFirst(ranks, index)
			s.updateStatus(networkKey, siteDisplay, transport, ranks, statusReason("site affinity"))
			return ranking, networkKey, siteKey, siteDisplay
		}
	}
	if lastSelected != "" {
		if index := smartRankIndex(ranks, lastSelected); index >= 0 && ranks[index].status.State != "open" && ranks[index].status.Score <= bestScore+s.switchMargin {
			ranks[index].status.Reason = "current candidate within switch margin"
			moveSmartRankFirst(ranks, index)
			s.updateStatus(networkKey, siteDisplay, transport, ranks, statusReason("switch margin retained current candidate"))
			return ranking, networkKey, siteKey, siteDisplay
		}
	}
	ranks[0].status.Reason = "lowest confidence-adjusted score"
	s.updateStatus(networkKey, siteDisplay, transport, ranks, statusReason("lowest confidence-adjusted score"))
	return ranking, networkKey, siteKey, siteDisplay
}

func (s *Smart) markSelected(candidate adapter.Outbound, networkKey, siteKey, siteDisplay, transport string, ranks []smartRank, attemptIndex int) {
	now := time.Now()
	key := networkKey + "\x00" + transport
	affinityKey := networkKey + "\x00" + siteKey + "\x00" + transport
	s.access.Lock()
	s.pruneAffinityLocked(now)
	previous := s.lastSelected[key]
	s.lastSelected[key] = candidate.Tag()
	if siteKey != "" {
		s.affinity[affinityKey] = smartAffinity{Candidate: candidate.Tag(), ExpiresAt: now.Add(s.siteStickiness)}
	}
	s.access.Unlock()
	s.latest.Store(candidate)
	reason := "selected best candidate"
	if attemptIndex > 0 {
		reason = "failover attempt " + itoaSmall(attemptIndex+1)
	}
	s.updateStatusSelected(networkKey, siteDisplay, transport, ranks, candidate.Tag(), reason)
	if previous != "" && previous != candidate.Tag() {
		s.interruptGroup.Interrupt(s.interruptExternal)
	}
}

func (s *Smart) updateStatus(networkKey, siteDisplay, transport string, ranks []smartRank, reason string) {
	selected := ""
	if len(ranks) > 0 {
		selected = ranks[0].outbound.Tag()
	}
	s.updateStatusSelected(networkKey, siteDisplay, transport, ranks, selected, reason)
}

func (s *Smart) updateStatusSelected(networkKey, siteDisplay, transport string, ranks []smartRank, selected, reason string) {
	pinned, _, _, _ := s.controlSnapshot(time.Now())
	statusCount := min(len(ranks), smartStatusCandidateLimit)
	s.statusAccess.Lock()
	statuses := s.status.Candidates[:0]
	if cap(statuses) < statusCount {
		statuses = make([]adapter.SmartCandidateStatus, 0, statusCount)
	}
	stateCounts := s.status.StateCounts
	if stateCounts == nil {
		stateCounts = make(map[string]int, 6)
	} else {
		clear(stateCounts)
	}
	for _, rank := range ranks {
		stateCounts[rank.status.State]++
	}
	if selectedIndex := smartRankIndex(ranks, selected); selectedIndex >= 0 && len(statuses) < statusCount {
		statuses = append(statuses, ranks[selectedIndex].status)
	}
	for index := range ranks {
		if len(statuses) >= statusCount {
			break
		}
		if ranks[index].outbound.Tag() == selected {
			continue
		}
		statuses = append(statuses, ranks[index].status)
	}
	profile := smartProfileInteractive
	if len(ranks) > 0 {
		profile = ranks[0].profile
	}
	s.status = adapter.SmartGroupStatus{
		Selected:                  selected,
		Pinned:                    pinned,
		Network:                   networkKey,
		Site:                      siteDisplay,
		Reason:                    transport + "/" + profile.String() + ": " + reason,
		UpdatedAt:                 time.Now(),
		CandidateCount:            len(ranks),
		CandidateDetailsCount:     len(statuses),
		CandidateDetailsTruncated: len(statuses) < len(ranks),
		StateCounts:               stateCounts,
		Candidates:                statuses,
	}
	s.statusAccess.Unlock()
}

func (s *Smart) setWarmingStatus(reason string) {
	s.statusAccess.Lock()
	s.status = adapter.SmartGroupStatus{
		Reason:      "warming: " + reason,
		UpdatedAt:   time.Now(),
		StateCounts: map[string]int{},
		Candidates:  []adapter.SmartCandidateStatus{},
	}
	s.statusAccess.Unlock()
}

func (s *Smart) reserveHalfOpen(rank smartRank, networkKey, siteKey, transport string) bool {
	if rank.status.State != "half_open" {
		return false
	}
	key := networkKey + "\x00" + siteKey + "\x00" + rank.outbound.Tag() + "\x00" + transport
	s.access.Lock()
	defer s.access.Unlock()
	if s.halfOpen == nil {
		s.halfOpen = make(map[string]struct{})
	}
	if _, loaded := s.halfOpen[key]; loaded {
		return false
	}
	s.halfOpen[key] = struct{}{}
	return true
}

func (s *Smart) releaseHalfOpen(candidate, networkKey, siteKey, transport string) {
	key := networkKey + "\x00" + siteKey + "\x00" + candidate + "\x00" + transport
	s.access.Lock()
	delete(s.halfOpen, key)
	s.access.Unlock()
}

func (s *Smart) pruneAffinityLocked(now time.Time) {
	limit := min(10000, max(1024, s.maxHistoryEntries/4))
	if len(s.affinity) < limit {
		return
	}
	for key, affinity := range s.affinity {
		if !affinity.ExpiresAt.After(now) {
			delete(s.affinity, key)
		}
	}
	for key := range s.affinity {
		if len(s.affinity) < limit {
			break
		}
		delete(s.affinity, key)
	}
}

func (s *Smart) clearBrokenPin(candidate, networkKey, siteKey, transport string) {
	_ = networkKey
	_ = siteKey
	_ = transport
	temporaryCleared := false
	s.control.access.Lock()
	if s.control.temporary == candidate {
		s.clearTemporaryLocked()
		temporaryCleared = true
	}
	s.control.access.Unlock()
	if temporaryCleared && s.logger != nil {
		s.logger.Warn("smart temporary override cleared after connection failure: ", candidate)
	}
	if s.logger != nil {
		s.control.access.Lock()
		pinned := s.control.pinned == candidate
		s.control.access.Unlock()
		if pinned {
			s.logger.Warn("smart permanent pin unavailable after connection failure; keeping manual pin: ", candidate)
		}
	}
}

func (s *Smart) onProviderUpdated(tag string) error {
	if s.closing.Load() {
		return nil
	}
	s.lifecycleAccess.Lock()
	retired := s.retired
	s.lifecycleAccess.Unlock()
	if retired {
		return nil
	}
	if _, loaded := s.providers[tag]; !loaded {
		return E.New("outbound provider not found: ", tag)
	}
	err := s.rebuildCandidates(tag)
	if errors.Is(err, errSmartNoCandidates) {
		s.setWarmingStatus("provider " + tag + " has no matching candidates")
	}
	if err != nil && s.logger != nil {
		s.logger.Error("rebuild smart candidates from provider ", tag, ": ", err)
	}
	if err == nil {
		s.reachForce.Store(true)
	}
	return err
}

func (s *Smart) rebuildCandidates(updatedProvider string) error {
	s.providerAccess.Lock()
	defer s.providerAccess.Unlock()
	var roots []adapter.Outbound
	for index, tag := range s.tags {
		candidate, loaded := s.outbound.Outbound(tag)
		if !loaded {
			return E.New("outbound ", index, " not found: ", tag)
		}
		roots = append(roots, candidate)
	}
	for _, providerTag := range s.providerTags {
		if providerTag != updatedProvider && s.outboundsCache[providerTag] != nil {
			roots = append(roots, s.outboundsCache[providerTag]...)
			continue
		}
		provider := s.providers[providerTag]
		if provider == nil {
			continue
		}
		var cache []adapter.Outbound
		for _, candidate := range provider.Outbounds() {
			if s.exclude != nil && s.exclude.MatchString(candidate.Tag()) {
				continue
			}
			if s.include != nil && !s.include.MatchString(candidate.Tag()) {
				continue
			}
			cache = append(cache, candidate)
		}
		s.outboundsCache[providerTag] = cache
		roots = append(roots, cache...)
	}
	var candidates []adapter.Outbound
	seen := make(map[string]bool)
	for _, root := range roots {
		s.flattenCandidate(root, make(map[string]bool), seen, &candidates)
	}
	if len(candidates) == 0 {
		return errSmartNoCandidates
	}
	candidateByTag := make(map[string]adapter.Outbound, len(candidates))
	for _, candidate := range candidates {
		candidateByTag[candidate.Tag()] = candidate
	}
	s.access.Lock()
	s.candidates = candidates
	s.candidateByTag = candidateByTag
	s.access.Unlock()
	if latest := s.latest.Load(); latest != nil && candidateByTag[latest.Tag()] == nil {
		s.latest.Store(nil)
	}
	s.control.access.Lock()
	if s.control.temporary != "" && candidateByTag[s.control.temporary] == nil {
		s.clearTemporaryLocked()
	}
	s.control.access.Unlock()
	s.setCandidatesReadyStatus(candidates)
	return nil
}

func (s *Smart) setCandidatesReadyStatus(candidates []adapter.Outbound) {
	statusCount := min(len(candidates), smartStatusCandidateLimit)
	statuses := make([]adapter.SmartCandidateStatus, statusCount)
	for index := range statusCount {
		statuses[index] = adapter.SmartCandidateStatus{
			Tag:    candidates[index].Tag(),
			State:  "warming",
			Reason: "awaiting observations",
		}
	}
	s.statusAccess.Lock()
	s.status = adapter.SmartGroupStatus{
		Reason:                    "warming: candidates loaded, awaiting observations",
		UpdatedAt:                 time.Now(),
		CandidateCount:            len(candidates),
		CandidateDetailsCount:     len(statuses),
		CandidateDetailsTruncated: len(statuses) < len(candidates),
		StateCounts:               map[string]int{"warming": len(candidates)},
		Candidates:                statuses,
	}
	s.statusAccess.Unlock()
}

func (s *Smart) flattenCandidate(candidate adapter.Outbound, stack, seen map[string]bool, destination *[]adapter.Outbound) {
	tag := candidate.Tag()
	if tag == "" || stack[tag] {
		return
	}
	if outboundGroup, isGroup := candidate.(adapter.OutboundGroup); isGroup {
		stack[tag] = true
		for _, childTag := range outboundGroup.All() {
			child, loaded := s.outbound.Outbound(childTag)
			if loaded {
				s.flattenCandidate(child, stack, seen, destination)
			}
		}
		delete(stack, tag)
		return
	}
	if seen[tag] {
		return
	}
	seen[tag] = true
	*destination = append(*destination, candidate)
}

func (s *Smart) networkFingerprint() string {
	if s.network == nil {
		return "network-default"
	}
	now := time.Now().UnixNano()
	if cached := s.fingerprint.Load(); cached != nil && now < cached.expiresAt {
		return cached.value
	}
	s.fingerprintLock.Lock()
	defer s.fingerprintLock.Unlock()
	if cached := s.fingerprint.Load(); cached != nil && now < cached.expiresAt {
		return cached.value
	}
	value := smartNetworkFingerprint(s.network.DefaultNetworkInterface(), s.network.WIFIState())
	s.fingerprint.Store(&smartFingerprintCache{
		value:     value,
		expiresAt: now + int64(smartNetworkFingerprintTTL),
	})
	return value
}

func smartNetworkFingerprint(networkInterface *adapter.NetworkInterface, wifi adapter.WIFIState) string {
	var identity strings.Builder
	if networkInterface != nil {
		identity.WriteString(networkInterface.Name)
		identity.WriteByte('|')
		identity.WriteString(itoaSmall(networkInterface.Index))
		identity.WriteByte('|')
		identity.WriteString(networkInterface.Type.String())
		identity.WriteByte('|')
		identity.WriteString(networkInterface.HardwareAddr.String())
		identity.WriteByte('|')
		identity.WriteString(itoaSmall(networkInterface.MTU))
		addresses := append([]netip.Prefix(nil), networkInterface.Addresses...)
		sort.Slice(addresses, func(i, j int) bool {
			return addresses[i].String() < addresses[j].String()
		})
		for _, address := range addresses {
			identity.WriteByte('|')
			identity.WriteString(address.Masked().String())
		}
		dnsServers := append([]string(nil), networkInterface.DNSServers...)
		sort.Strings(dnsServers)
		for _, dnsServer := range dnsServers {
			identity.WriteByte('|')
			identity.WriteString(dnsServer)
		}
	}
	identity.WriteByte('|')
	identity.WriteString(wifi.SSID)
	identity.WriteByte('|')
	identity.WriteString(wifi.BSSID)
	return "network-" + hashSmartIdentity(identity.String())
}

func (s *Smart) loadHistory() {
	content, err := os.ReadFile(s.historyPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			s.logger.Warn("load smart history: ", err)
		}
		return
	}
	var header struct {
		Version int `json:"version"`
	}
	if err = json.Unmarshal(content, &header); err != nil {
		s.logger.Warn("decode smart history: ", err)
		return
	}
	var snapshot smartStoreSnapshot
	if header.Version == smartHistoryFileVersion {
		var historyFile smartHistoryFile
		if err = json.Unmarshal(content, &historyFile); err != nil {
			s.logger.Warn("decode smart history: ", err)
			return
		}
		s.loadedHistory = cloneSmartHistorySnapshots(historyFile.Groups)
		snapshot = historyFile.Groups[s.Tag()]
	} else if err = json.Unmarshal(content, &snapshot); err != nil {
		s.logger.Warn("decode smart history: ", err)
		return
	}
	s.store.restore(snapshot)
}

func (s *Smart) flushHistory() {
	s.lifecycleAccess.Lock()
	entry := s.historyEntry
	released := s.historyReleased
	s.lifecycleAccess.Unlock()
	if s.historyPath == "" || entry == nil || released {
		return
	}
	entry.fileAccess.Lock()
	defer entry.fileAccess.Unlock()
	smartHistoryPool.Lock()
	stores := make(map[string]smartHistoryStore, len(entry.stores))
	for tag, historyStore := range entry.stores {
		stores[tag] = historyStore
	}
	groups := cloneSmartHistorySnapshots(entry.persisted)
	smartHistoryPool.Unlock()
	for tag, historyStore := range stores {
		snapshot := historyStore.store.snapshot(time.Now(), historyStore.retention, historyStore.maxEntries)
		groups[tag] = snapshot
	}
	content, err := json.Marshal(smartHistoryFile{
		Version: smartHistoryFileVersion,
		Groups:  groups,
	})
	if err != nil {
		s.logger.Warn("encode smart history: ", err)
		return
	}
	if err = os.MkdirAll(filepath.Dir(s.historyPath), 0o755); err != nil {
		s.logger.Warn("create smart history directory: ", err)
		return
	}
	temporaryFile, err := os.CreateTemp(filepath.Dir(s.historyPath), "."+filepath.Base(s.historyPath)+".*.tmp")
	if err != nil {
		s.logger.Warn("create smart history temporary file: ", err)
		return
	}
	temporaryPath := temporaryFile.Name()
	defer os.Remove(temporaryPath)
	if err = temporaryFile.Chmod(0o600); err == nil {
		_, err = temporaryFile.Write(content)
	}
	if closeErr := temporaryFile.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		s.logger.Warn("write smart history: ", err)
		return
	}
	if err = os.Rename(temporaryPath, s.historyPath); err != nil {
		s.logger.Warn("publish smart history: ", err)
		return
	}
	smartHistoryPool.Lock()
	if smartHistoryPool.entries[s.historyPath] == entry {
		entry.persisted = groups
	}
	smartHistoryPool.Unlock()
}

func (s *Smart) releaseHistory() {
	s.lifecycleAccess.Lock()
	if s.historyReleased || s.historyEntry == nil {
		s.lifecycleAccess.Unlock()
		return
	}
	entry := s.historyEntry
	s.historyReleased = true
	s.lifecycleAccess.Unlock()
	smartHistoryPool.Lock()
	tag := s.Tag()
	entry.references[tag]--
	if entry.references[tag] <= 0 {
		delete(entry.references, tag)
		delete(entry.stores, tag)
		delete(entry.controls, tag)
	}
	if len(entry.references) == 0 && smartHistoryPool.entries[s.historyPath] == entry {
		delete(smartHistoryPool.entries, s.historyPath)
	}
	smartHistoryPool.Unlock()
}

func cloneSmartHistorySnapshots(source map[string]smartStoreSnapshot) map[string]smartStoreSnapshot {
	result := make(map[string]smartStoreSnapshot, len(source))
	for tag, snapshot := range source {
		snapshot.Metrics = append([]smartMetric(nil), snapshot.Metrics...)
		result[tag] = snapshot
	}
	return result
}

func smartSiteIdentity(metadata *adapter.InboundContext, destination M.Socksaddr) (string, string) {
	host := ""
	if metadata != nil {
		switch {
		case metadata.Domain != "":
			host = metadata.Domain
		}
	}
	if host == "" && destination.IsDomain() {
		host = destination.Fqdn
	}
	if host != "" {
		if net.ParseIP(host) == nil {
			if etld, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
				host = etld
			}
		}
		return host, "site-" + hashSmartIdentity(host)
	}
	var address netip.Addr
	if metadata != nil && len(metadata.DestinationAddresses) > 0 {
		address = metadata.DestinationAddresses[0]
	} else {
		address = destination.Addr
	}
	if address.IsValid() {
		display := address.String()
		return display, "site-" + hashSmartIdentity(display)
	}
	return "", ""
}

func smartEstimateReason(estimate smartEstimate) string {
	switch estimate.State {
	case "open":
		return "circuit open until " + estimate.CircuitUntil.Format(time.RFC3339)
	case "half_open":
		return "breaker cooldown elapsed; limited recovery trial"
	case "warming":
		return "collecting baseline samples"
	case "suspect":
		return "confidence-adjusted reliability is low"
	case "unknown":
		return "no observations; exploration budget applies"
	default:
		return "healthy"
	}
}

func smartRankIndex(ranks []smartRank, tag string) int {
	for index := range ranks {
		if ranks[index].outbound.Tag() == tag {
			return index
		}
	}
	return -1
}

func moveSmartRankFirst(ranks []smartRank, index int) {
	if index <= 0 {
		return
	}
	selected := ranks[index]
	copy(ranks[1:index+1], ranks[:index])
	ranks[0] = selected
}

func hashSmartIdentity(value string) string {
	hash := fnv.New64a()
	_, _ = hash.Write([]byte(value))
	return hex.EncodeToString(hash.Sum(nil))
}

func safeSmartFileName(value string) string {
	if value == "" {
		return "default"
	}
	var builder strings.Builder
	for _, character := range value {
		switch {
		case character >= 'a' && character <= 'z':
			builder.WriteRune(character)
		case character >= 'A' && character <= 'Z':
			builder.WriteRune(character)
		case character >= '0' && character <= '9':
			builder.WriteRune(character)
		case character == '-' || character == '_':
			builder.WriteRune(character)
		default:
			builder.WriteByte('_')
		}
	}
	return builder.String()
}

func itoaSmall(value int) string {
	if value == 0 {
		return "0"
	}
	var buffer [20]byte
	index := len(buffer)
	for value > 0 {
		index--
		buffer[index] = byte('0' + value%10)
		value /= 10
	}
	return string(buffer[index:])
}

type smartObservedConn struct {
	N.ExtendedConn
	startedAt   time.Time
	readBytes   atomic.Int64
	writeBytes  atomic.Int64
	firstRead   sync.Once
	closeOnce   sync.Once
	onFirstByte func(time.Duration)
	onClose     func(int64, time.Duration)
}

func newSmartObservedConn(conn net.Conn, startedAt time.Time, onFirstByte func(time.Duration), onClose func(int64, time.Duration)) net.Conn {
	return &smartObservedConn{
		ExtendedConn: bufio.NewExtendedConn(conn),
		startedAt:    startedAt,
		onFirstByte:  onFirstByte,
		onClose:      onClose,
	}
}

func (c *smartObservedConn) Read(buffer []byte) (int, error) {
	n, err := c.ExtendedConn.Read(buffer)
	c.observeRead(int64(n))
	return n, err
}

func (c *smartObservedConn) Write(buffer []byte) (int, error) {
	n, err := c.ExtendedConn.Write(buffer)
	c.observeWrite(int64(n))
	return n, err
}

func (c *smartObservedConn) ReadBuffer(buffer *buf.Buffer) error {
	before := buffer.Len()
	err := c.ExtendedConn.ReadBuffer(buffer)
	readBytes := buffer.Len() - before
	c.observeRead(int64(readBytes))
	return err
}

func (c *smartObservedConn) WriteBuffer(buffer *buf.Buffer) error {
	writeBytes := buffer.Len()
	err := c.ExtendedConn.WriteBuffer(buffer)
	if err == nil && writeBytes > 0 {
		c.observeWrite(int64(writeBytes))
	}
	return err
}

func (c *smartObservedConn) Close() error {
	c.closeOnce.Do(func() {
		if c.onClose != nil {
			c.onClose(c.readBytes.Load()+c.writeBytes.Load(), time.Since(c.startedAt))
		}
	})
	return c.ExtendedConn.Close()
}

func (c *smartObservedConn) UnwrapReader() (io.Reader, []N.CountFunc) {
	return c.ExtendedConn, []N.CountFunc{c.observeRead}
}

func (c *smartObservedConn) UnwrapWriter() (io.Writer, []N.CountFunc) {
	return c.ExtendedConn, []N.CountFunc{c.observeWrite}
}

func (c *smartObservedConn) Upstream() any {
	return c.ExtendedConn
}

func (c *smartObservedConn) observeRead(n int64) {
	if n <= 0 {
		return
	}
	c.readBytes.Add(n)
	c.firstRead.Do(func() {
		if c.onFirstByte != nil {
			c.onFirstByte(time.Since(c.startedAt))
		}
	})
}

func (c *smartObservedConn) observeWrite(n int64) {
	if n > 0 {
		c.writeBytes.Add(n)
	}
}
