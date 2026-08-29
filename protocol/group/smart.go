package group

import (
	"context"
	"encoding/hex"
	"errors"
	"hash/fnv"
	"io"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/nodefilter"
	"github.com/sagernet/sing-box/common/nodeweight"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/group/trafficfamily"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"

	"golang.org/x/net/publicsuffix"
)

const (
	defaultSmartProbeInterval        = 10 * time.Minute
	defaultSmartProbeCycleTimeout    = 30 * time.Second
	defaultSmartProbeTimeout         = 5 * time.Second
	defaultSmartProbeConcurrency     = 2
	defaultSmartAttemptTimeout       = 4 * time.Second
	defaultSmartSiteStickiness       = 30 * time.Minute
	defaultSmartSwitchConfirm        = 2 * time.Minute
	defaultSmartSwitchConfirmSamples = 3
	defaultSmartSwitchCooldown       = 10 * time.Minute
	defaultSmartMinSwitchImprovement = 100 * time.Millisecond
	defaultSmartHedgeDelay           = 450 * time.Millisecond
	minSmartHedgeDelay               = 250 * time.Millisecond
	// Give a healthy, already-established path a little more time for its
	// first byte before starting a competing dial.  This reduces Safari/Google
	// asset bursts that otherwise create needless hedges; hard dial failures
	// still advance immediately through the normal retry path.
	maxSmartHedgeDelay       = 900 * time.Millisecond
	defaultSmartSwitchMargin = 0.15
	smartSwitchAuditLimit    = 128
	// Active probes already rotate through the catalog. Keep the score bonus
	// small so exploration does not displace a proven path during real traffic.
	defaultSmartExploration = 0.02
	defaultSmartMinSamples  = 3
	// Passive bulk gating only consumes bytes observed on real connections.
	// 512 KiB/s is deliberately conservative: it catches the measured
	// YouTube/GCore stall without rejecting ordinary interactive traffic.
	defaultSmartPassiveThroughputFloorBPS = 512 * 1024
	defaultSmartPassiveThroughputSamples  = 2
	defaultSmartMaxAttempts               = 3
	defaultSmartBreakerFailures           = 3
	defaultSmartBreakerCooldown           = 2 * time.Minute
	defaultSmartHalfLife                  = 30 * time.Minute
	// Homelab/router default: 48h + 4k is enough for site stickiness without
	// multi-hundred-MB metric maps (5 groups × 50k was a common RSS blow-up).
	defaultSmartHistoryRetention  = 48 * time.Hour
	defaultSmartMaxHistoryEntries = 4096
	smartStatusCandidateLimit     = 32
	smartNetworkFingerprintTTL    = 2 * time.Second
	// Background profiling follows traffic demand. A cold/idle group only
	// samples a small rotating subset; real traffic wakes a larger bounded
	// cycle. This keeps large catch-all groups from consuming the same probe
	// budget as an actively routed regional group.
	defaultSmartActivityWindow    = 15 * time.Minute
	defaultSmartIdleProbeInterval = 30 * time.Minute
	defaultSmartColdProbeBudget   = 4
	defaultSmartActiveProbeBudget = 16
)

func sniffOrDomain(metadata *adapter.InboundContext) string {
	if metadata == nil {
		return ""
	}
	if metadata.SniffHost != "" {
		return metadata.SniffHost
	}
	return metadata.Domain
}

func RegisterSmart(registry *outbound.Registry) {
	outbound.Register[option.SmartOutboundOptions](registry, C.TypeSmart, NewSmart)
}

var (
	_ adapter.SmartGroup            = (*Smart)(nil)
	_ adapter.PreMatchOutboundGroup = (*Smart)(nil)
)

var errSmartNoCandidates = errors.New("smart group has no leaf candidates")

type smartAffinity struct {
	Candidate string
	ExpiresAt time.Time
}

type smartRank struct {
	outbound             adapter.Outbound
	status               adapter.SmartCandidateStatus
	profile              smartTrafficProfile
	estimate             smartEstimate
	eligible             bool
	passiveThroughputLow bool
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
	attempt         smartDialAttempt
	conn            net.Conn
	err             error
	elapsed         time.Duration
	hadPriorFailure bool
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
	manualExclude   *nodefilter.Matcher
	nodeWeights     *nodeweight.Matcher
	useAllProviders bool

	access              sync.RWMutex
	candidates          []adapter.Outbound
	candidateByTag      map[string]adapter.Outbound
	candidateProbeKey   map[string]string
	control             *smartControlState
	lastSelected        map[string]string
	affinity            map[string]smartAffinity
	switchChallenges    map[string]smartSwitchChallenge
	performanceCooldown map[string]time.Time
	halfOpen            map[string]struct{}
	latest              common.TypedValue[adapter.Outbound]
	fingerprint         atomic.Pointer[smartFingerprintCache]
	fingerprintLock     sync.Mutex

	statusAccess sync.RWMutex
	status       adapter.SmartGroupStatus

	store                     *smartStore
	policyBackend             smartPolicyBackend
	probeURL                  string
	probeInterval             time.Duration
	probeCycleTimeout         time.Duration
	probeTimeout              time.Duration
	probeConcurrency          int
	maxAttempts               int
	attemptTimeout            time.Duration
	siteStickiness            time.Duration
	switchConfirm             time.Duration
	switchConfirmSamples      int
	switchCooldown            time.Duration
	switchMargin              float64
	switchMinImprovement      time.Duration
	exploration               float64
	minSamples                int
	passiveThroughputFloorBPS uint64
	passiveThroughputSamples  int
	halfLife                  time.Duration
	breakerFailures           int
	breakerCooldown           time.Duration
	historyRetention          time.Duration
	maxHistoryEntries         int
	interruptGroup            *interrupt.Group
	interruptExternal         bool
	interruptMode             string
	interruptIdle             time.Duration
	interruptLongAge          time.Duration
	interruptGrace            time.Duration
	switchesTotal             atomic.Uint64
	performanceSwitches       atomic.Uint64
	failureFailovers          atomic.Uint64
	coldStarts                atomic.Uint64
	switchAuditAccess         sync.Mutex
	switchAudit               []adapter.SmartSwitchAudit
	switchesForceAll          atomic.Uint64
	switchesSelective         atomic.Uint64
	connectionsInterrupted    atomic.Uint64
	connectionsKept           atomic.Uint64
	streamFailureWakes        atomic.Uint64
	probing                   atomic.Bool
	probeCursor               atomic.Uint64
	lastActivityUnixNano      atomic.Int64
	closing                   atomic.Bool
	cancel                    context.CancelFunc
	worker                    sync.WaitGroup
	lifecycleAccess           sync.Mutex
	postStarted               bool
	retired                   bool
	workerStarted             bool
	probeRegistry             *smartProbeRegistry
	releaseProbeRegistry      func()
	probeStartupDelay         time.Duration
	probeNow                  chan struct{}
	families                  *trafficfamily.Resolver
}

type smartSwitchChallenge struct {
	Candidate string
	Since     time.Time
	Count     int
}

func NewSmart(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SmartOutboundOptions) (adapter.Outbound, error) {
	manualExclude, err := nodefilter.New([]string(options.ExcludeNodes))
	if err != nil {
		return nil, err
	}
	weightRules := make([]nodeweight.Rule, len(options.NodeWeights))
	for index, rule := range options.NodeWeights {
		weightRules[index] = nodeweight.Rule{Match: rule.Match, Weight: rule.Weight}
	}
	nodeWeights, err := nodeweight.New(weightRules)
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
	probeConcurrency := options.ProbeConcurrency
	if probeConcurrency <= 0 {
		probeConcurrency = defaultSmartProbeConcurrency
	}
	if probeConcurrency > 4 {
		probeConcurrency = 4
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
	switchConfirm := time.Duration(options.SwitchConfirm)
	if switchConfirm <= 0 {
		switchConfirm = defaultSmartSwitchConfirm
	}
	if switchConfirm < 5*time.Second {
		return nil, E.New("smart switch_confirm must be at least 5s")
	}
	switchConfirmSamples := options.SwitchConfirmSamples
	if switchConfirmSamples <= 0 {
		switchConfirmSamples = defaultSmartSwitchConfirmSamples
	}
	switchCooldown := time.Duration(options.SwitchCooldown)
	if switchCooldown <= 0 {
		switchCooldown = defaultSmartSwitchCooldown
	}
	switchMargin := defaultSmartSwitchMargin
	if options.SwitchMargin != nil {
		switchMargin = max(0, *options.SwitchMargin)
	}
	if switchMargin >= 1 {
		return nil, E.New("smart switch_margin must be less than 1")
	}
	switchMinImprovement := time.Duration(options.SwitchMinImprovement)
	if switchMinImprovement == 0 {
		switchMinImprovement = defaultSmartMinSwitchImprovement
	}
	if switchMinImprovement < 0 {
		return nil, E.New("smart switch_min_improvement must not be negative")
	}
	exploration := defaultSmartExploration
	if options.Exploration != nil {
		exploration = max(0, *options.Exploration)
	}
	minSamples := options.MinSamples
	if minSamples <= 0 {
		minSamples = defaultSmartMinSamples
	}
	passiveThroughputFloorBPS := options.PassiveThroughputFloorBPS
	if passiveThroughputFloorBPS == 0 {
		passiveThroughputFloorBPS = defaultSmartPassiveThroughputFloorBPS
	}
	passiveThroughputSamples := options.PassiveThroughputSamples
	if passiveThroughputSamples <= 0 {
		passiveThroughputSamples = defaultSmartPassiveThroughputSamples
	}
	if passiveThroughputSamples < 2 {
		return nil, E.New("smart passive_throughput_samples must be at least 2")
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
	interruptMode := options.InterruptPolicy.Mode
	if interruptMode == "" {
		if options.InterruptConnections {
			interruptMode = "all"
		} else {
			interruptMode = "none"
		}
	}
	if interruptMode != "none" && interruptMode != "selective" && interruptMode != "all" {
		return nil, E.New("invalid smart interrupt_policy.mode: ", interruptMode)
	}
	interruptIdle := time.Duration(options.InterruptPolicy.IdleThreshold)
	if interruptIdle <= 0 {
		interruptIdle = 10 * time.Second
	}
	if interruptIdle < 5*time.Second {
		return nil, E.New("smart interrupt_policy.idle_threshold must be at least 5s")
	}
	interruptLongAge := time.Duration(options.InterruptPolicy.LongConnectionAge)
	if interruptLongAge <= 0 {
		interruptLongAge = 30 * time.Second
	}
	if interruptLongAge < 15*time.Second {
		return nil, E.New("smart interrupt_policy.long_connection_age must be at least 15s")
	}
	interruptGrace := time.Duration(options.InterruptPolicy.GracePeriod)
	if interruptGrace <= 0 {
		interruptGrace = 3 * time.Second
	}
	if options.InterruptPolicy.Mode != "" && options.InterruptConnections && logger != nil {
		logger.Warn("smart interrupt_policy overrides deprecated interrupt_exist_connections")
	}
	historyPath := options.HistoryPath
	if historyPath != "" && logger != nil {
		// S2: field kept for config compat; no effect since rc44.
		logger.Warn("smart history_path is deprecated since rc44, no effect (health is process-local and rebuilt after each start)")
	}
	store := newSmartStore(halfLife, breakerFailures, breakerCooldown)
	store.setBounds(historyRetention, maxHistoryEntries)
	policyBackend := newSmartPolicyBackend(smartPolicyBackendConfig{
		Exploration: exploration, SwitchMargin: switchMargin,
		SwitchConfirm: switchConfirmSamples, SwitchConfirmWindow: switchConfirm.Milliseconds(),
		SwitchCooldown: switchCooldown.Milliseconds(),
	})
	if policyBackend == nil && logger != nil {
		logger.Warn("smart policy backend unavailable; using reference Go policy")
	} else if policyBackend != nil && logger != nil {
		logger.Info("smart policy backend: zig")
	}
	probeRegistry, releaseProbeRegistry := acquireSmartProbeRegistry(ctx)
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
		manualExclude:   manualExclude,
		nodeWeights:     nodeWeights,
		useAllProviders: options.UseAllProviders,

		candidateByTag:      make(map[string]adapter.Outbound),
		candidateProbeKey:   make(map[string]string),
		control:             &smartControlState{},
		lastSelected:        make(map[string]string),
		affinity:            make(map[string]smartAffinity),
		switchChallenges:    make(map[string]smartSwitchChallenge),
		performanceCooldown: make(map[string]time.Time),
		halfOpen:            make(map[string]struct{}),
		store:               store,
		policyBackend:       policyBackend,

		probeURL:                  options.URL,
		probeInterval:             probeInterval,
		probeCycleTimeout:         probeCycleTimeout,
		probeTimeout:              probeTimeout,
		probeConcurrency:          probeConcurrency,
		maxAttempts:               maxAttempts,
		attemptTimeout:            attemptTimeout,
		siteStickiness:            siteStickiness,
		switchConfirm:             switchConfirm,
		switchConfirmSamples:      switchConfirmSamples,
		switchCooldown:            switchCooldown,
		switchMargin:              switchMargin,
		switchMinImprovement:      switchMinImprovement,
		exploration:               exploration,
		minSamples:                minSamples,
		passiveThroughputFloorBPS: passiveThroughputFloorBPS,
		passiveThroughputSamples:  passiveThroughputSamples,
		halfLife:                  halfLife,
		breakerFailures:           breakerFailures,
		breakerCooldown:           breakerCooldown,
		historyRetention:          historyRetention,
		maxHistoryEntries:         maxHistoryEntries,
		interruptGroup:            interrupt.NewGroup(),
		interruptExternal:         options.InterruptConnections,
		interruptMode:             interruptMode,
		interruptIdle:             interruptIdle,
		interruptLongAge:          interruptLongAge,
		interruptGrace:            interruptGrace,
		probeRegistry:             probeRegistry,
		releaseProbeRegistry:      releaseProbeRegistry,
		probeStartupDelay:         probeRegistry.startupDelay(),
		probeNow:                  make(chan struct{}, 1),
		families:                  trafficfamily.NewResolver(),
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

func (s *Smart) stopWorker() {
	s.lifecycleAccess.Lock()
	s.retired = true
	if s.cancel != nil {
		s.cancel()
	}
	s.lifecycleAccess.Unlock()
}

func (s *Smart) startWorkerLocked() {
	if !s.postStarted || s.retired || s.workerStarted {
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
	s.stopWorker()
	s.unregisterProviderCallbacks()
	// Bound wait: in-flight URL tests + shared probe slots can stall each group
	// for several seconds. Five smart groups closed serially would otherwise
	// exceed FatalStopTimeout (10s) and crash with "sing-box did not close!".
	s.waitWorkerStop(2 * time.Second)
	s.access.Lock()
	clear(s.candidateByTag)
	clear(s.lastSelected)
	clear(s.affinity)
	clear(s.switchChallenges)
	clear(s.performanceCooldown)
	clear(s.halfOpen)
	s.candidates = nil
	s.candidateByTag = make(map[string]adapter.Outbound)
	s.candidateProbeKey = make(map[string]string)
	s.lastSelected = make(map[string]string)
	s.affinity = make(map[string]smartAffinity)
	s.switchChallenges = make(map[string]smartSwitchChallenge)
	s.performanceCooldown = make(map[string]time.Time)
	s.halfOpen = make(map[string]struct{})
	s.access.Unlock()
	s.providerAccess.Lock()
	clear(s.providers)
	clear(s.outboundsCache)
	s.providers = make(map[string]adapter.Provider)
	s.outboundsCache = make(map[string][]adapter.Outbound)
	s.providerHandles = make(map[string]*list.Element[adapter.ProviderUpdateCallback])
	s.providerAccess.Unlock()
	s.store.clear()
	if s.policyBackend != nil {
		s.policyBackend.Close()
		s.policyBackend = nil
	}
	if s.releaseProbeRegistry != nil {
		s.releaseProbeRegistry()
		s.releaseProbeRegistry = nil
	}
	return nil
}

// waitWorkerStop waits for the probe worker up to timeout after cancel.
// Stragglers must honor s.closing / cancelled ctx and not touch cleared maps.
func (s *Smart) waitWorkerStop(timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		s.worker.Wait()
		close(done)
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		if s.logger != nil {
			s.logger.Warn("smart probe worker did not stop within ", timeout, "; continuing close for high availability")
		}
	}
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
	if s.probeStartupDelay > 0 {
		timer := time.NewTimer(s.probeStartupDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
	if ctx.Err() != nil || s.closing.Load() {
		return
	}
	// Cold start once. Default cap 45s (was 2m) so multi-smart Close stays in HA
	// budget; catalogs rotate on probe_interval. Explicit probe_cycle_timeout
	// above 45s is honored when set.
	cold := 45 * time.Second
	if s.probeCycleTimeout > cold {
		cold = s.probeCycleTimeout
	}
	probeCtx, cancel := context.WithTimeout(ctx, cold)
	_, _ = s.probeWithBudget(probeCtx, defaultSmartColdProbeBudget)
	cancel()
	nextInterval := s.nextProbeInterval(time.Now())
	probeTimer := time.NewTimer(nextInterval)
	defer probeTimer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-probeTimer.C:
			if s.closing.Load() {
				return
			}
			probeCtx, cancel := context.WithTimeout(ctx, s.probeCycleTimeout)
			_, _ = s.probeWithBudget(probeCtx, s.scheduledProbeBudget(time.Now()))
			cancel()
			probeTimer.Reset(s.nextProbeInterval(time.Now()))
		case <-s.probeNow:
			if s.closing.Load() {
				return
			}
			probeCtx, cancel := context.WithTimeout(ctx, s.probeCycleTimeout)
			_, _ = s.probeWithBudget(probeCtx, s.requestedProbeBudget(time.Now()))
			cancel()
			if !probeTimer.Stop() {
				select {
				case <-probeTimer.C:
				default:
				}
			}
			probeTimer.Reset(s.nextProbeInterval(time.Now()))
		}
	}
}

func (s *Smart) activeAt(now time.Time) bool {
	last := s.lastActivityUnixNano.Load()
	return last > 0 && now.Sub(time.Unix(0, last)) <= defaultSmartActivityWindow
}

func (s *Smart) nextProbeInterval(now time.Time) time.Duration {
	if s.activeAt(now) {
		return s.probeInterval
	}
	return max(s.probeInterval, defaultSmartIdleProbeInterval)
}

func (s *Smart) scheduledProbeBudget(now time.Time) int {
	if s.activeAt(now) {
		return defaultSmartActiveProbeBudget
	}
	return 1
}

func (s *Smart) requestedProbeBudget(now time.Time) int {
	if s.activeAt(now) {
		return defaultSmartActiveProbeBudget
	}
	return defaultSmartColdProbeBudget
}

func (s *Smart) noteTrafficActivity() {
	now := time.Now()
	previous := s.lastActivityUnixNano.Swap(now.UnixNano())
	if previous == 0 || now.Sub(time.Unix(0, previous)) > defaultSmartActivityWindow {
		s.requestProbe()
	}
}

func (s *Smart) requestProbe() {
	select {
	case s.probeNow <- struct{}{}:
	default:
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

// SelectPreMatchOutbound picks a stable leaf for transparent pre-match without
// advancing hedge/retry/selection state (those remain on the L4 path).
func (s *Smart) SelectPreMatchOutbound(metadata *adapter.InboundContext, selectOutbound func(adapter.Outbound) (adapter.Outbound, adapter.PreMatchAction)) (adapter.Outbound, adapter.PreMatchAction) {
	leaf := s.preMatchLeaf(metadata)
	if leaf == nil {
		return nil, adapter.PreMatchContinue
	}
	return selectOutbound(leaf)
}

func (s *Smart) preMatchLeaf(metadata *adapter.InboundContext) adapter.Outbound {
	now := time.Now()
	pinned, temporary, _, _ := s.controlSnapshot(now)
	s.access.RLock()
	defer s.access.RUnlock()
	pick := func(tag string) adapter.Outbound {
		if tag == "" {
			return nil
		}
		return s.candidateByTag[tag]
	}
	if detour := pick(temporary); detour != nil {
		return detour
	}
	if detour := pick(pinned); detour != nil {
		return detour
	}
	if selected := s.latest.Load(); selected != nil {
		if _, ok := s.candidateByTag[selected.Tag()]; ok {
			return selected
		}
	}
	if len(s.candidates) > 0 {
		return s.candidates[0]
	}
	_ = metadata
	return nil
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
	status.SwitchesTotal = s.switchesTotal.Load()
	status.PerformanceSwitches = s.performanceSwitches.Load()
	status.FailureFailovers = s.failureFailovers.Load()
	status.ColdStarts = s.coldStarts.Load()
	status.SwitchesForceAll = s.switchesForceAll.Load()
	status.SwitchesSelective = s.switchesSelective.Load()
	status.ConnectionsInterrupted = s.connectionsInterrupted.Load()
	status.ConnectionsKept = s.connectionsKept.Load()
	status.StreamFailureWakes = s.streamFailureWakes.Load()
	s.switchAuditAccess.Lock()
	status.RecentSwitches = append([]adapter.SmartSwitchAudit(nil), s.switchAudit...)
	s.switchAuditAccess.Unlock()
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
	if s.policyBackend != nil {
		s.policyBackend.Reset()
	}
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
	if s.policyBackend != nil {
		s.policyBackend.Reset()
	}
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
	s.noteTrafficActivity()
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
		adapter.NoteRealOutbound(ctx, candidate)
		s.markSelected(candidate, networkKey, siteKey, siteDisplay, transport, ranks, result.attempt.attemptIndex, result.hadPriorFailure)
		conn = s.interruptGroup.NewConnWithKey(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsProviderConnectionFromContext(ctx), smartConnectionKey(networkKey, siteKey, transport, candidate.Tag()))
		return newSmartObservedConn(conn, time.Now().Add(-result.elapsed), func(firstByte time.Duration) {
			s.store.observeFirstByte(time.Now(), networkKey, siteKey, s.candidateProfileID(candidate.Tag()), transport, firstByte)
		}, func(bytes int64, duration time.Duration) {
			s.store.observeThroughput(time.Now(), networkKey, siteKey, s.candidateProfileID(candidate.Tag()), transport, bytes, duration)
		}, func() {
			// A stream can become unusable after DialContext succeeds (for
			// example a stale multiplex session or a reset upstream socket).
			// Wake the control-plane probe, but do not directly penalize the
			// candidate: the shared 204 probe remains the source of truth.
			s.streamFailureWakes.Add(1)
			s.requestProbe()
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
		// A well-sampled, highly reliable current candidate should get a
		// little more first-byte time.  The first dial is still started
		// immediately; this only delays a competing dial, avoiding needless
		// Safari/Google connection races.  If the dial actually fails, the
		// normal error path starts the next candidate without waiting.
		if started == 1 && attempts[0].rank.status.State == "healthy" &&
			attempts[0].rank.status.Reliability >= 0.9 && attempts[0].rank.status.Samples >= 10 {
			delay += 250 * time.Millisecond
			if delay > 1200*time.Millisecond {
				delay = 1200 * time.Millisecond
			}
		}
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
				s.observeDial(time.Now(), networkKey, siteKey, candidate.Tag(), transport, false, result.elapsed)
				s.clearBrokenPin(candidate.Tag(), networkKey, siteKey, transport)
				// A real data-plane failure must wake recovery itself.  Dashboard
				// latency tests may also refresh the shared profile, but production
				// failover must never depend on a user opening the proxy page.  The
				// buffered request channel coalesces concurrent failures and the
				// shared probe registry single-flights work per endpoint.
				s.requestProbe()
				attemptErrors = append(attemptErrors, E.Cause(result.err, "smart candidate ", candidate.Tag()))
				if started < len(attempts) {
					startAttempt(attempts[started])
					started++
					active++
				}
				resetHedge()
				continue
			}
			s.observeDial(time.Now(), networkKey, siteKey, candidate.Tag(), transport, true, result.elapsed)
			result.hadPriorFailure = len(attemptErrors) > 0
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
	s.noteTrafficActivity()
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
			s.observeDial(time.Now(), networkKey, siteKey, candidate.Tag(), transport, false, elapsed)
			s.clearBrokenPin(candidate.Tag(), networkKey, siteKey, transport)
			s.requestProbe()
			attemptErrors = append(attemptErrors, E.Cause(err, "smart candidate ", candidate.Tag()))
			continue
		}
		s.observeDial(time.Now(), networkKey, siteKey, candidate.Tag(), transport, true, elapsed)
		adapter.NoteRealOutbound(ctx, candidate)
		s.markSelected(candidate, networkKey, siteKey, siteDisplay, transport, ranks, attemptIndex, attemptIndex > 0)
		observed := newSmartObservedPacketConn(conn, startedAt, smartUDPExpectsResponse(destination), func(flowElapsed time.Duration) {
			s.observeDial(time.Now(), networkKey, siteKey, candidate.Tag(), transport, false, flowElapsed)
			s.clearBrokenPin(candidate.Tag(), networkKey, siteKey, transport)
			s.requestProbe()
		})
		return s.interruptGroup.NewPacketConnWithKey(observed, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsProviderConnectionFromContext(ctx), smartConnectionKey(networkKey, siteKey, transport, candidate.Tag())), nil
	}
	s.updateStatusSelected(networkKey, siteDisplay, transport, ranks, "", "all eligible UDP candidates failed")
	if len(attemptErrors) == 0 {
		return nil, E.New("all smart UDP candidates are circuit-open or recovery-busy")
	}
	return nil, errors.Join(attemptErrors...)
}

func smartUDPExpectsResponse(destination M.Socksaddr) bool {
	switch destination.Port {
	case 53, 443, 3478:
		return true
	default:
		return false
	}
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
	return s.probeWithBudget(ctx, 0)
}

func (s *Smart) probeWithBudget(ctx context.Context, budget int) (map[string]uint16, error) {
	result := make(map[string]uint16)
	if ctx.Err() != nil || s.closing.Load() {
		return result, ctx.Err()
	}
	if s.probing.Swap(true) {
		return result, nil
	}
	defer s.probing.Store(false)
	s.access.RLock()
	candidates := append([]adapter.Outbound(nil), s.candidates...)
	probeKeys := make(map[string]string, len(s.candidateProbeKey))
	for tag, key := range s.candidateProbeKey {
		probeKeys[tag] = key
	}
	s.access.RUnlock()
	if len(candidates) == 0 || s.closing.Load() {
		return result, nil
	}
	if len(candidates) > 1 {
		advance := 1
		if budget > 0 && budget < len(candidates) {
			advance = budget
		}
		start := int(s.probeCursor.Add(uint64(advance))-uint64(advance)) % len(candidates)
		candidates = append(candidates[start:], candidates[:start]...)
	}
	if budget > 0 && len(candidates) > budget {
		candidates = candidates[:budget]
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
	// Keep exploration from competing with real browser traffic.  The old
	// fixed five workers caused Safari's parallel Google asset requests to
	// fan out across many candidates and briefly starve the selected path.
	probeConcurrency := s.probeConcurrency
	// Test/embedded constructors may not pass through NewSmart. Preserve the
	// bounded default there as well; a zero value must never silently create a
	// probe cycle with no workers.
	if probeConcurrency <= 0 {
		probeConcurrency = defaultSmartProbeConcurrency
	}
	workerCount := min(probeConcurrency, len(candidates))
	for range workerCount {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for candidate := range jobs {
				if ctx.Err() != nil || s.closing.Load() {
					results <- probeResult{candidate: candidate, err: context.Canceled}
					continue
				}
				identity := probeKeys[candidate.Tag()]
				key := smartProbeKey(identity, s.probeURL, s.probeTimeout)
				var delay uint16
				var err error
				if s.probeRegistry != nil {
					// Admission is process-wide and may legitimately wait behind
					// another group. Apply the per-node timeout only after a slot is
					// acquired inside the registry; otherwise a healthy node can be
					// mislabeled merely because the shared queue took five seconds.
					delay, err = s.probeRegistry.run(ctx, key, s.probeURL, s.probeTimeout, s.probeInterval, candidate)
				} else {
					// Test/embedded constructors created before the shared registry
					// contract retain the stock direct probe path.
					testCtx, cancel := context.WithTimeout(ctx, s.probeTimeout)
					delay, err = urltest.URLTest(testCtx, s.probeURL, candidate)
					cancel()
				}
				penalize := err != nil && !errors.Is(err, errSharedSmartProbeDeferred) && ctx.Err() == nil && !s.closing.Load()
				results <- probeResult{candidate: candidate, delay: delay, err: err, penalize: penalize}
			}
		}()
	}
	type probeSummary struct {
		collected []probeResult
		successes int
	}
	networkKey := s.networkFingerprint()
	summaryDone := make(chan probeSummary, 1)
	go func() {
		summary := probeSummary{collected: make([]probeResult, 0, len(candidates))}
		published := false
		for probe := range results {
			summary.collected = append(summary.collected, probe)
			if probe.err != nil {
				continue
			}
			summary.successes++
			result[probe.candidate.Tag()] = probe.delay
			if s.closing.Load() {
				continue
			}
			s.observeDial(time.Now(), networkKey, "", probe.candidate.Tag(), N.NetworkTCP, true, time.Duration(probe.delay)*time.Millisecond)
			if !published {
				// The first successful basic probe makes a cold group usable while
				// the remaining candidates continue to build profiles in parallel.
				ranking, _, _, _ := s.rankPooled(s.ctx, N.NetworkTCP, M.Socksaddr{})
				ranking.Release()
				published = true
			}
		}
		summaryDone <- summary
	}()
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
	summary := <-summaryDone
	if s.closing.Load() {
		// Shutdown: skip store mutations so Close can clear maps safely.  A
		// probe-cycle deadline is different: completed observations remain
		// valuable and must be committed so inactive/large groups eventually
		// build a baseline over multiple bounded cycles.
		return result, ctx.Err()
	}
	commonFailure := len(summary.collected) > 1 && summary.successes == 0
	for _, probe := range summary.collected {
		if probe.err != nil && probe.penalize && !commonFailure && (s.probeRegistry == nil || s.probeRegistry.dead(smartProbeKey(probeKeys[probe.candidate.Tag()], s.probeURL, s.probeTimeout))) {
			s.observeDial(time.Now(), networkKey, "", probe.candidate.Tag(), N.NetworkTCP, false, s.probeTimeout)
		}
	}
	if summary.successes > 0 {
		// Publish the baseline immediately.  Ranking is otherwise refreshed only
		// by a real dial, which makes traffic-idle groups look permanently warming
		// even though their active probes have already populated the store.
		ranking, _, _, _ := s.rankPooled(s.ctx, N.NetworkTCP, M.Socksaddr{})
		ranking.Release()
	}
	if commonFailure {
		if s.logger != nil {
			s.logger.Warn("smart probe suppressed candidate penalties because every candidate failed")
		}
		return result, E.New("all smart probes failed; candidate penalties suppressed")
	}
	// Preserve the deadline for callers while retaining every observation that
	// completed before it.  Scheduled callers intentionally ignore this error;
	// explicit URLTest callers can still distinguish a partial cycle.
	return result, ctx.Err()
}

func (s *Smart) rank(ctx context.Context, transport string, destination M.Socksaddr) ([]smartRank, string, string, string) {
	ranking, networkKey, siteKey, siteDisplay := s.rankPooled(ctx, transport, destination)
	ranks := append([]smartRank(nil), ranking.ranks...)
	ranking.Release()
	return ranks, networkKey, siteKey, siteDisplay
}

// observeDial is the single observation fan-out.  The Go EndpointProfile is
// still the source of truth for API/status consumers; when the Zig backend is
// enabled it receives the same event keyed by canonical endpoint identity.
func (s *Smart) observeDial(now time.Time, network, site, candidate, transport string, success bool, elapsed time.Duration) {
	profileID := s.candidateProfileID(candidate)
	s.store.observeDial(now, network, site, profileID, transport, success, elapsed)
	if s.policyBackend == nil {
		return
	}
	s.access.RLock()
	identity := s.candidateProbeKey[candidate]
	s.access.RUnlock()
	if identity != "" {
		s.policyBackend.Observe(smartSelectionKey(network, site, transport), smartPolicyID(identity), success, elapsed, now)
	}
}

// candidateProfileID maps provider display tags to the canonical endpoint
// identity. Subscription copies such as "JP 1" and "JP 2" therefore share
// one health portrait in the Go store as well as in the Zig policy backend.
// A tag is retained as the fallback for embedded/test candidates without a
// probe identity.
func (s *Smart) candidateProfileID(candidate string) string {
	if s == nil || candidate == "" {
		return candidate
	}
	s.access.RLock()
	identity := s.candidateProbeKey[candidate]
	s.access.RUnlock()
	if identity == "" || identity == candidate {
		return candidate
	}
	return "endpoint:" + identity
}

func (s *Smart) rankPooled(ctx context.Context, transport string, destination M.Socksaddr) (*smartRanking, string, string, string) {
	now := time.Now()
	pinned, temporary, _, _ := s.controlSnapshot(now)
	networkKey := s.networkFingerprint()
	siteDisplay, siteKey := s.resolveSmartSiteIdentity(adapter.ContextFrom(ctx), destination)
	s.access.RLock()
	ranking := acquireSmartRanking(len(s.candidates))
	ranking.candidates = append(ranking.candidates, s.candidates...)
	lastSelected := s.lastSelected[smartSelectionKey(networkKey, siteKey, transport)]
	affinity := s.affinity[networkKey+"\x00"+siteKey+"\x00"+transport]
	s.access.RUnlock()

	totalSamples := 0.0
	policyCandidates := make([]smartPolicyCandidate, 0, len(ranking.candidates))
	policyIDs := make(map[uint64]struct{}, len(ranking.candidates))
	profile := smartProfileInteractive
	if transport == N.NetworkUDP {
		profile = smartProfileUDP
	}
	for _, candidate := range ranking.candidates {
		if !common.Contains(candidate.Network(), transport) {
			continue
		}
		estimate := s.store.estimate(now, networkKey, siteKey, s.candidateProfileID(candidate.Tag()), transport, s.minSamples)
		sharedProbeDead := false
		if s.probeRegistry != nil && common.Contains(candidate.Network(), N.NetworkTCP) {
			s.access.RLock()
			identity := s.candidateProbeKey[candidate.Tag()]
			s.access.RUnlock()
			sharedProbeDead = s.probeRegistry.dead(smartProbeKey(identity, s.probeURL, s.probeTimeout))
		}
		if sharedProbeDead {
			estimate.State = "open"
		}
		identity := ""
		s.access.RLock()
		identity = s.candidateProbeKey[candidate.Tag()]
		s.access.RUnlock()
		policyID := smartPolicyID(identity)
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
			// Hard health gates run before weights and soft score. A circuit-open
			// endpoint must never become eligible merely because it has a large
			// configured weight.
			eligible: estimate.State != "open",
			status: adapter.SmartCandidateStatus{
				Tag:            candidate.Tag(),
				State:          estimate.State,
				Reliability:    estimate.Reliability,
				ConnectMS:      estimate.ConnectMS,
				ConnectP95MS:   estimate.ConnectP95MS,
				FirstByteMS:    estimate.FirstByteMS,
				FirstByteP95MS: estimate.FirstByteP95MS,
				ThroughputBPS:  estimate.ThroughputBPS,
				Samples:        estimate.Samples,
			},
		})
		if s.policyBackend != nil && identity != "" {
			// Several provider lines can describe one endpoint.  Let the policy
			// kernel see one candidate so suffix-renamed duplicates cannot create
			// contradictory state; the host still keeps all lines for fallback.
			if _, exists := policyIDs[policyID]; !exists {
				policyIDs[policyID] = struct{}{}
				policyCandidates = append(policyCandidates, smartPolicyCandidate{
					ID: policyID, Reliability: estimate.Reliability, ConnectMS: smartConnectScoreMS(estimate),
					FirstByteMS: smartFirstByteScoreMS(estimate), JitterMS: estimate.JitterMS,
					Throughput: estimate.ThroughputBPS, Samples: estimate.Samples,
					Weight: s.nodeWeights.Explain(candidate.Tag()).Weight,
					State:  smartPolicyState(estimate.State), Eligible: estimate.State != "open",
				})
			}
		}
	}
	// Apply the passive bulk gate only after the traffic profile is known. This
	// changes eligibility for future dials; it never interrupts an existing
	// stream and never schedules an active resource probe.
	if profile == smartProfileBulk {
		for index := range ranking.ranks {
			if !passiveThroughputBelowFloor(ranking.ranks[index].estimate, s.passiveThroughputFloorBPS, s.passiveThroughputSamples) {
				continue
			}
			ranking.ranks[index].estimate.State = "open"
			ranking.ranks[index].status.State = "open"
			ranking.ranks[index].eligible = false
			ranking.ranks[index].status.Reason = "passive throughput below floor"
			ranking.ranks[index].passiveThroughputLow = true
			identity := ""
			s.access.RLock()
			identity = s.candidateProbeKey[ranking.ranks[index].outbound.Tag()]
			s.access.RUnlock()
			policyID := smartPolicyID(identity)
			for policyIndex := range policyCandidates {
				if policyCandidates[policyIndex].ID == policyID {
					policyCandidates[policyIndex].State = smartPolicyState("open")
					policyCandidates[policyIndex].Eligible = false
				}
			}
		}
	}
	for index := range ranking.ranks {
		weightMatch := s.nodeWeights.Explain(ranking.ranks[index].outbound.Tag())
		weight := weightMatch.Weight
		ranking.ranks[index].profile = profile
		ranking.ranks[index].status.Score = smartScoreForProfile(ranking.ranks[index].estimate, profile, s.exploration, totalSamples) / weight
		ranking.ranks[index].status.Weight = weight
		ranking.ranks[index].status.WeightRule = weightMatch.Rule
		ranking.ranks[index].status.WeightExact = weightMatch.Exact
		if !ranking.ranks[index].passiveThroughputLow {
			ranking.ranks[index].status.Reason = smartEstimateReason(ranking.ranks[index].estimate)
		}
		ranking.ranks[index].estimate = smartEstimate{}
	}
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
		if index := smartRankIndex(ranks, pinned); index >= 0 && ranks[index].status.State != "open" && ranks[index].status.State != "half_open" {
			// A permanent manual selection is authoritative while its circuit is
			// usable. RTT and score changes must never silently overrule a human.
			ranks[index].eligible = true
			ranks[index].status.Reason = "manual pin"
			moveSmartRankFirst(ranks, index)
			s.updateStatus(networkKey, siteDisplay, transport, ranks, "manual pin")
			return ranking, networkKey, siteKey, siteDisplay
		} else {
			manualPinUnavailable = true
			s.releaseConfirmedBrokenPin(pinned, "candidate circuit opened")
		}
	}
	if !hasEligibleSmartRank(ranks) {
		s.updateStatus(networkKey, siteDisplay, transport, ranks, statusReason("no service-reachable candidates"))
		return ranking, networkKey, siteKey, siteDisplay
	}
	if s.policyBackend != nil {
		decision := s.policyBackend.Choose(smartSelectionKey(networkKey, siteKey, transport), policyCandidates, profile, now)
		if decision.SelectedID != 0 {
			selectedIndex := -1
			for index := range ranks {
				identity := ""
				s.access.RLock()
				identity = s.candidateProbeKey[ranks[index].outbound.Tag()]
				s.access.RUnlock()
				if smartPolicyID(identity) != decision.SelectedID {
					continue
				}
				selectedIndex = index
				break
			}
			if selectedIndex >= 0 {
				currentIndex := smartRankIndex(ranks, lastSelected)
				if currentIndex >= 0 && currentIndex != selectedIndex &&
					!smartAbsoluteImprovement(ranks[selectedIndex], ranks[currentIndex], s.switchMinImprovement) {
					// The Zig kernel already applies relative margin, confirmation,
					// and cooldown. This additional absolute floor prevents a tiny
					// score change from moving a healthy browser path when the p95
					// latency gain is below the user-visible threshold.
					ranks[currentIndex].status.Reason = "healthy current candidate retained below latency floor"
					moveSmartRankFirst(ranks, currentIndex)
					s.updateStatus(networkKey, siteDisplay, transport, ranks, "healthy current candidate retained below latency floor")
					return ranking, networkKey, siteKey, siteDisplay
				}
			}
			if selectedIndex >= 0 {
				reason := "zig policy retained candidate"
				if decision.Switched {
					reason = "zig policy confirmed candidate"
				}
				ranks[selectedIndex].status.Reason = reason
				moveSmartRankFirst(ranks, selectedIndex)
				s.updateStatus(networkKey, siteDisplay, transport, ranks, reason)
				return ranking, networkKey, siteKey, siteDisplay
			}
		}
		// A corrupt/unsupported backend decision must fail safe to the best
		// host-ranked candidate, without re-entering the Go confirmation FSM.
		s.updateStatus(networkKey, siteDisplay, transport, ranks, "zig policy fallback to host ranking")
		return ranking, networkKey, siteKey, siteDisplay
	}
	bestScore := ranks[0].status.Score
	selectionKey := smartSelectionKey(networkKey, siteKey, transport)
	current := lastSelected
	if affinity.Candidate != "" && affinity.ExpiresAt.After(now) {
		current = affinity.Candidate
	}
	if current != "" {
		if index := smartRankIndex(ranks, current); index >= 0 && ranks[index].status.State != "open" {
			currentScore := ranks[index].status.Score
			bestCandidate := ranks[0].outbound.Tag()
			switchConfirmed := false
			switchReason := "current candidate within switch margin"
			switchStatusReason := "switch margin retained current candidate"
			switch {
			case current == bestCandidate:
				s.clearSwitchChallenge(selectionKey)
			case smartEquivalentLine(current, bestCandidate):
				s.clearSwitchChallenge(selectionKey)
				switchReason = "equivalent subscription line retained"
				switchStatusReason = "healthy equivalent line retained"
			case !smartRelativeImprovement(bestScore, currentScore, s.switchMargin) ||
				!smartAbsoluteImprovement(ranks[0], ranks[index], s.switchMinImprovement):
				s.clearSwitchChallenge(selectionKey)
			case s.performanceSwitchCoolingDown(selectionKey, now):
				s.clearSwitchChallenge(selectionKey)
				switchReason = "better candidate retained during switch cooldown"
				switchStatusReason = "healthy current candidate retained during switch cooldown"
			case s.confirmSwitchChallenge(selectionKey, bestCandidate, now):
				switchConfirmed = true
			default:
				switchReason = "better candidate awaiting sustained confirmation"
				switchStatusReason = "healthy current candidate retained during switch confirmation"
			}
			if !switchConfirmed {
				ranks[index].status.Reason = switchReason
				moveSmartRankFirst(ranks, index)
				s.updateStatus(networkKey, siteDisplay, transport, ranks, statusReason(switchStatusReason))
				return ranking, networkKey, siteKey, siteDisplay
			}
		}
	}
	ranks[0].status.Reason = "lowest confidence-adjusted score"
	s.updateStatus(networkKey, siteDisplay, transport, ranks, statusReason("lowest confidence-adjusted score"))
	return ranking, networkKey, siteKey, siteDisplay
}

func (s *Smart) markSelected(candidate adapter.Outbound, networkKey, siteKey, siteDisplay, transport string, ranks []smartRank, attemptIndex int, hadPriorFailure bool) {
	now := time.Now()
	key := smartSelectionKey(networkKey, siteKey, transport)
	affinityKey := networkKey + "\x00" + siteKey + "\x00" + transport
	s.access.Lock()
	s.pruneAffinityLocked(now)
	previous := s.lastSelected[key]
	previousRank, previousFound := smartRankByTag(ranks, previous)
	currentRank, currentFound := smartRankByTag(ranks, candidate.Tag())
	failureSwitch := hadPriorFailure || (previousFound && previousRank.status.State == "open")
	// Several requests can rank concurrently and finish in a different order.
	// Do not let a late healthy completion undo a just-committed selection.
	if s.policyBackend == nil && previous != "" && previous != candidate.Tag() && !failureSwitch {
		coolingDown := s.performanceCooldown[key].After(now)
		materiallyBetter := previousFound && currentFound &&
			smartRelativeImprovement(currentRank.status.Score, previousRank.status.Score, s.switchMargin) &&
			smartAbsoluteImprovement(currentRank, previousRank, s.switchMinImprovement)
		if coolingDown || !materiallyBetter {
			s.access.Unlock()
			s.updateStatusSelected(networkKey, siteDisplay, transport, ranks, previous, "late healthy result retained current candidate")
			return
		}
	}
	s.lastSelected[key] = candidate.Tag()
	delete(s.switchChallenges, key)
	if s.policyBackend == nil && previous != "" && previous != candidate.Tag() && !failureSwitch {
		if s.performanceCooldown == nil {
			s.performanceCooldown = make(map[string]time.Time)
		}
		s.performanceCooldown[key] = now.Add(s.switchCooldown)
	}
	if siteKey != "" {
		s.affinity[affinityKey] = smartAffinity{Candidate: candidate.Tag(), ExpiresAt: now.Add(s.siteStickiness)}
	}
	s.access.Unlock()
	s.latest.Store(candidate)
	reason := "selected best candidate"
	category := "cold_start"
	if attemptIndex > 0 {
		if hadPriorFailure {
			reason = "failover attempt " + itoaSmall(attemptIndex+1)
		} else {
			reason = "hedged connection won"
		}
	}
	if previous == "" {
		s.coldStarts.Add(1)
	} else if previous != candidate.Tag() {
		if failureSwitch {
			category = "failure_failover"
			s.failureFailovers.Add(1)
			reason = "failed candidate bypassed confirmation"
		} else {
			category = "performance_switch"
			s.performanceSwitches.Add(1)
		}
		s.appendSwitchAudit(adapter.SmartSwitchAudit{
			Network: networkKey, Site: siteDisplay, Transport: transport,
			Previous: previous, Current: candidate.Tag(), Category: category, Reason: reason,
			PreviousState: previousRank.status.State, CurrentState: currentRank.status.State,
			PreviousScore: previousRank.status.Score, CurrentScore: currentRank.status.Score,
			OccurredAt: now,
		})
	}
	s.updateStatusSelected(networkKey, siteDisplay, transport, ranks, candidate.Tag(), reason)
	if previous != "" && previous != candidate.Tag() {
		s.switchesTotal.Add(1)
		s.interruptPreviousCandidate(networkKey, siteKey, transport, previous, candidate.Tag())
	}
}

func smartRankByTag(ranks []smartRank, tag string) (smartRank, bool) {
	for _, rank := range ranks {
		if rank.outbound.Tag() == tag {
			return rank, true
		}
	}
	return smartRank{}, false
}

func smartRelativeImprovement(bestScore, currentScore, margin float64) bool {
	if bestScore >= currentScore {
		return false
	}
	if margin <= 0 {
		return true
	}
	return currentScore > bestScore/(1-margin)
}

func smartAbsoluteImprovement(best, current smartRank, minimum time.Duration) bool {
	if minimum <= 0 {
		return true
	}
	bestLatency := smartRankLatencyMS(best)
	currentLatency := smartRankLatencyMS(current)
	if bestLatency <= 0 || currentLatency <= 0 {
		// Do not switch a healthy path on a score that has no comparable latency
		// evidence. Hard failures are handled before this gate.
		return false
	}
	return currentLatency-bestLatency >= float64(minimum)/float64(time.Millisecond)
}

func smartRankLatencyMS(rank smartRank) float64 {
	if rank.status.FirstByteP95MS > 0 {
		return rank.status.FirstByteP95MS
	}
	if rank.status.ConnectP95MS > 0 {
		return rank.status.ConnectP95MS
	}
	if rank.status.FirstByteMS > 0 {
		return rank.status.FirstByteMS
	}
	return rank.status.ConnectMS
}

// smartEquivalentLine recognizes only suffixes generated by the provider
// duplicate-tag resolver. It intentionally does not strip user-visible numeric
// names such as "BGP 1" and "BGP 2", which can be genuinely different lines.
func smartEquivalentLine(left, right string) bool {
	return left != right && smartLineFamily(left) == smartLineFamily(right)
}

func smartLineFamily(tag string) string {
	if len(tag) > 10 && tag[len(tag)-10:len(tag)-8] == " #" && isLowerHex(tag[len(tag)-8:]) {
		return tag[:len(tag)-10]
	}
	if strings.HasSuffix(tag, ")") {
		if open := strings.LastIndex(tag, " ("); open >= 0 && open+2 < len(tag)-1 && isDecimal(tag[open+2:len(tag)-1]) {
			return tag[:open]
		}
	}
	return tag
}

func isLowerHex(value string) bool {
	if len(value) != 8 {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			if char < 'a' || char > 'f' {
				return false
			}
		}
	}
	return true
}

func isDecimal(value string) bool {
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return value != ""
}

func (s *Smart) performanceSwitchCoolingDown(key string, now time.Time) bool {
	s.access.RLock()
	until := s.performanceCooldown[key]
	s.access.RUnlock()
	return until.After(now)
}

func (s *Smart) appendSwitchAudit(event adapter.SmartSwitchAudit) {
	s.switchAuditAccess.Lock()
	if len(s.switchAudit) >= smartSwitchAuditLimit {
		copy(s.switchAudit, s.switchAudit[len(s.switchAudit)-smartSwitchAuditLimit+1:])
		s.switchAudit = s.switchAudit[:smartSwitchAuditLimit-1]
	}
	s.switchAudit = append(s.switchAudit, event)
	s.switchAuditAccess.Unlock()
}

func (s *Smart) clearSwitchChallenge(key string) {
	s.access.Lock()
	delete(s.switchChallenges, key)
	s.access.Unlock()
}

func (s *Smart) confirmSwitchChallenge(key, candidate string, now time.Time) bool {
	s.access.Lock()
	defer s.access.Unlock()
	challenge := s.switchChallenges[key]
	if challenge.Candidate != candidate || challenge.Since.IsZero() {
		s.switchChallenges[key] = smartSwitchChallenge{Candidate: candidate, Since: now, Count: 1}
		return false
	}
	challenge.Count++
	s.switchChallenges[key] = challenge
	if challenge.Count < s.switchConfirmSamples || now.Sub(challenge.Since) < s.switchConfirm {
		return false
	}
	delete(s.switchChallenges, key)
	return true
}

func smartSelectionKey(networkKey, siteKey, transport string) string {
	return networkKey + "\x00" + siteKey + "\x00" + transport
}

func smartConnectionKey(networkKey, siteKey, transport, candidate string) string {
	return smartSelectionKey(networkKey, siteKey, transport) + "\x00" + candidate
}

func (s *Smart) interruptPreviousCandidate(networkKey, siteKey, transport, previous, current string) {
	if s.interruptMode == "none" {
		return
	}
	forceAll := s.interruptMode == "all"
	if !forceAll && s.probeRegistry != nil {
		s.access.RLock()
		identity := s.candidateProbeKey[previous]
		s.access.RUnlock()
		forceAll = s.probeRegistry.dead(smartProbeKey(identity, s.probeURL, s.probeTimeout))
	}
	if !forceAll {
		forceAll = s.store.candidateDead(s.candidateProfileID(previous), time.Now())
	}
	// A performance-driven switch must be invisible to established flows. New
	// connections use the better candidate while existing healthy connections
	// drain naturally. Only a confirmed dead candidate justifies interruption.
	if !forceAll {
		if s.logger != nil {
			s.logger.Info("smart switch ", previous, " -> ", current, " reason=confirmed_performance kept_existing=true")
		}
		return
	}
	policy := interrupt.InterruptPolicy{
		IdleThreshold: s.interruptIdle,
		LongConnAge:   s.interruptLongAge,
		GracePeriod:   s.interruptGrace,
		ForceAll:      forceAll,
		TargetKey:     smartConnectionKey(networkKey, siteKey, transport, previous),
		OnInterrupted: func() { s.connectionsInterrupted.Add(1) },
	}
	result := s.interruptGroup.InterruptSelective(policy)
	if forceAll {
		s.switchesForceAll.Add(1)
	}
	s.connectionsKept.Add(uint64(result.Kept))
	if s.logger != nil {
		reason := "latency"
		if forceAll {
			reason = "node_dead"
		}
		s.logger.Info("smart switch ", previous, " -> ", current, " reason=", reason,
			" interrupted=", result.Interrupted, " deferred=", result.Deferred, " idle=", result.Idle,
			" short=", result.Short, " kept=", result.Kept, " kept_long=", result.KeptLong)
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
	estimate := s.store.estimate(time.Now(), networkKey, siteKey, s.candidateProfileID(candidate), transport, s.minSamples)
	if estimate.State == "open" || estimate.State == "half_open" {
		s.releaseConfirmedBrokenPin(candidate, "confirmed connection failure threshold reached")
	}
}

// releaseConfirmedBrokenPin turns a failed manual choice back into normal Smart
// operation. The pin is intentionally not restored after recovery: a new pin
// requires a new explicit user selection.
func (s *Smart) releaseConfirmedBrokenPin(candidate, reason string) bool {
	if candidate == "" {
		return false
	}
	s.control.access.Lock()
	if s.control.pinned != candidate {
		s.control.access.Unlock()
		return false
	}
	s.control.pinned = ""
	s.control.access.Unlock()
	if s.policyBackend != nil {
		s.policyBackend.Reset()
	}
	if s.logger != nil {
		s.logger.Warn("smart manual pin released: ", reason, " tag=", candidate)
	}
	return true
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
	if err == nil {
		// Providers commonly publish after PostStart.  The cold-start probe may
		// therefore have observed an empty catalog; do not leave a traffic-idle
		// group unprofiled until the next periodic interval.
		s.requestProbe()
	}
	if errors.Is(err, errSmartNoCandidates) {
		s.setWarmingStatus("provider " + tag + " has no matching candidates")
	}
	if err != nil && s.logger != nil {
		s.logger.Error("rebuild smart candidates from provider ", tag, ": ", err)
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
			if s.manualExclude.Match(candidate.Tag()) {
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
	stack := make(map[string]bool)
	for _, root := range roots {
		s.flattenCandidate(root, stack, seen, &candidates)
	}
	if len(candidates) == 0 {
		return errSmartNoCandidates
	}
	candidateByTag := make(map[string]adapter.Outbound, len(candidates))
	candidateProbeKey := make(map[string]string, len(candidates))
	for _, candidate := range candidates {
		candidateByTag[candidate.Tag()] = candidate
		candidateProbeKey[candidate.Tag()] = s.probeIdentityLocked(candidate)
	}
	s.access.Lock()
	s.candidates = candidates
	s.candidateByTag = candidateByTag
	s.candidateProbeKey = candidateProbeKey
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
	if s.manualExclude.Match(tag) {
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

func smartSiteIdentity(metadata *adapter.InboundContext, destination M.Socksaddr) (string, string) {
	return resolveSmartSiteIdentity(nil, metadata, destination)
}

func (s *Smart) resolveSmartSiteIdentity(metadata *adapter.InboundContext, destination M.Socksaddr) (string, string) {
	if s == nil {
		return smartSiteIdentity(metadata, destination)
	}
	return resolveSmartSiteIdentity(s.families, metadata, destination)
}

func resolveSmartSiteIdentity(families *trafficfamily.Resolver, metadata *adapter.InboundContext, destination M.Socksaddr) (string, string) {
	host := ""
	if metadata != nil {
		host = sniffOrDomain(metadata)
	}
	if host == "" && destination.IsDomain() {
		host = destination.Fqdn
	}
	if host != "" {
		if net.ParseIP(host) == nil {
			family := ""
			if families != nil {
				family = families.Resolve(host, smartFamilyClientScope(metadata), time.Now()).ID
			} else {
				family = trafficfamily.Classify(host).ID
			}
			if family != "" && family != "unknown" && !strings.HasPrefix(family, "site:") {
				display := "service:" + family
				return display, "site-" + hashSmartIdentity(display)
			}
			if strings.HasPrefix(family, "site:") {
				host = strings.TrimPrefix(family, "site:")
			} else if etld, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
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

func smartFamilyClientScope(metadata *adapter.InboundContext) string {
	if metadata == nil {
		return "default"
	}
	return metadata.Inbound + "\x00" + metadata.Source.Addr.String() + "\x00" + metadata.User
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
	failureOnce sync.Once
	onFirstByte func(time.Duration)
	onClose     func(int64, time.Duration)
	onFailure   func()
}

func newSmartObservedConn(conn net.Conn, startedAt time.Time, onFirstByte func(time.Duration), onClose func(int64, time.Duration), onFailure func()) net.Conn {
	return &smartObservedConn{
		ExtendedConn: bufio.NewExtendedConn(conn),
		startedAt:    startedAt,
		onFirstByte:  onFirstByte,
		onClose:      onClose,
		onFailure:    onFailure,
	}
}

func (c *smartObservedConn) Read(buffer []byte) (int, error) {
	n, err := c.ExtendedConn.Read(buffer)
	c.observeRead(int64(n))
	c.observeFailure(err)
	return n, err
}

func (c *smartObservedConn) Write(buffer []byte) (int, error) {
	n, err := c.ExtendedConn.Write(buffer)
	c.observeWrite(int64(n))
	c.observeFailure(err)
	return n, err
}

func (c *smartObservedConn) ReadBuffer(buffer *buf.Buffer) error {
	before := buffer.Len()
	err := c.ExtendedConn.ReadBuffer(buffer)
	readBytes := buffer.Len() - before
	c.observeRead(int64(readBytes))
	c.observeFailure(err)
	return err
}

func (c *smartObservedConn) WriteBuffer(buffer *buf.Buffer) error {
	writeBytes := buffer.Len()
	err := c.ExtendedConn.WriteBuffer(buffer)
	if err == nil && writeBytes > 0 {
		c.observeWrite(int64(writeBytes))
	}
	c.observeFailure(err)
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

func (c *smartObservedConn) observeFailure(err error) {
	if !isSmartStreamFailure(err) {
		return
	}
	c.failureOnce.Do(func() {
		if c.onFailure != nil {
			c.onFailure()
		}
	})
}

func isSmartStreamFailure(err error) bool {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
		return false
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return true
	}
	return errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.ECONNABORTED) ||
		errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ETIMEDOUT) ||
		errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.EHOSTUNREACH)
}

// smartObservedPacketConn turns real transactional UDP blackholes into Smart
// node evidence. It deliberately ignores one-way UDP and idle timeouts after
// any response, so telemetry and long-lived QUIC sessions are not penalized.
type smartObservedPacketConn struct {
	net.PacketConn
	startedAt      time.Time
	expectResponse bool
	writePackets   atomic.Uint64
	readPackets    atomic.Uint64
	closeOnce      sync.Once
	onNoResponse   func(time.Duration)
}

func newSmartObservedPacketConn(conn net.PacketConn, startedAt time.Time, expectResponse bool, onNoResponse func(time.Duration)) net.PacketConn {
	base := &smartObservedPacketConn{
		PacketConn:     conn,
		startedAt:      startedAt,
		expectResponse: expectResponse,
		onNoResponse:   onNoResponse,
	}
	reader, hasReader := conn.(N.PacketReader)
	writer, hasWriter := conn.(N.PacketWriter)
	switch {
	case hasReader && hasWriter:
		return &smartObservedExtendedPacketConn{smartObservedPacketConn: base, reader: reader, writer: writer}
	case hasReader:
		return &smartObservedPacketReaderConn{smartObservedPacketConn: base, reader: reader}
	case hasWriter:
		return &smartObservedPacketWriterConn{smartObservedPacketConn: base, writer: writer}
	default:
		return base
	}
}

func (c *smartObservedPacketConn) observeRead(count int) {
	if count > 0 {
		c.readPackets.Add(1)
	}
}

func (c *smartObservedPacketConn) observeWrite(count int) {
	if count > 0 {
		c.writePackets.Add(1)
	}
}

func (c *smartObservedPacketConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	count, source, err := c.PacketConn.ReadFrom(payload)
	c.observeRead(count)
	return count, source, err
}

func (c *smartObservedPacketConn) WriteTo(payload []byte, destination net.Addr) (int, error) {
	count, err := c.PacketConn.WriteTo(payload, destination)
	if err == nil {
		c.observeWrite(count)
	}
	return count, err
}

func (c *smartObservedPacketConn) Close() error {
	c.closeOnce.Do(func() {
		elapsed := time.Since(c.startedAt)
		if c.expectResponse && c.writePackets.Load() > 0 && c.readPackets.Load() == 0 && elapsed >= time.Second && c.onNoResponse != nil {
			c.onNoResponse(elapsed)
		}
	})
	return c.PacketConn.Close()
}

func (c *smartObservedPacketConn) Upstream() any         { return c.PacketConn }
func (*smartObservedPacketConn) ReaderReplaceable() bool { return false }
func (*smartObservedPacketConn) WriterReplaceable() bool { return false }

type smartObservedPacketReaderConn struct {
	*smartObservedPacketConn
	reader N.PacketReader
}

func (c *smartObservedPacketReaderConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	before := buffer.Len()
	destination, err := c.reader.ReadPacket(buffer)
	c.observeRead(buffer.Len() - before)
	return destination, err
}

type smartObservedPacketWriterConn struct {
	*smartObservedPacketConn
	writer N.PacketWriter
}

func (c *smartObservedPacketWriterConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	count := buffer.Len()
	err := c.writer.WritePacket(buffer, destination)
	if err == nil {
		c.observeWrite(count)
	}
	return err
}

type smartObservedExtendedPacketConn struct {
	*smartObservedPacketConn
	reader N.PacketReader
	writer N.PacketWriter
}

func (c *smartObservedExtendedPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	before := buffer.Len()
	destination, err := c.reader.ReadPacket(buffer)
	c.observeRead(buffer.Len() - before)
	return destination, err
}

func (c *smartObservedExtendedPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	count := buffer.Len()
	err := c.writer.WritePacket(buffer, destination)
	if err == nil {
		c.observeWrite(count)
	}
	return err
}
