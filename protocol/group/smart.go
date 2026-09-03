package group

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash/fnv"
	"io"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
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
	"golang.org/x/net/dns/dnsmessage"

	"golang.org/x/net/publicsuffix"
)

const (
	defaultSmartProbeInterval = 10 * time.Minute
	// The probe must not depend on a hostname whose DNS is routed through the
	// very Smart group being measured.  A literal Cloudflare address keeps the
	// first probe bootstrap-safe; urltest supplies the matching TLS SNI.
	defaultSmartProbeURL                = "https://1.1.1.1/cdn-cgi/trace"
	defaultSmartProbeCycleTimeout       = 30 * time.Second
	defaultSmartProbeTimeout            = 5 * time.Second
	defaultSmartProbeConcurrency        = 2
	defaultSmartUDPProbeTimeout         = 2 * time.Second
	defaultSmartUDPProbeTargetCount     = 2
	defaultSmartRecoveryProbeTimeout    = 2 * time.Second
	defaultSmartRecoveryProbeCooldown   = 10 * time.Second
	defaultSmartAttemptTimeout          = 4 * time.Second
	defaultSmartEstablishedStallTimeout = 10 * time.Second
	minSmartEstablishedStallTimeout     = 5 * time.Second
	maxSmartEstablishedStallTimeout     = 2 * time.Minute
	defaultSmartSiteStickiness          = 30 * time.Minute
	defaultSmartSwitchConfirm           = 2 * time.Minute
	defaultSmartSwitchConfirmSamples    = 3
	defaultSmartSwitchCooldown          = 10 * time.Minute
	defaultSmartMinSwitchImprovement    = 100 * time.Millisecond
	defaultSmartHedgeDelay              = 450 * time.Millisecond
	minSmartHedgeDelay                  = 250 * time.Millisecond
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
	smartStatusContextLimit       = 32
	smartNetworkFingerprintTTL    = 2 * time.Second
	// Background profiling follows traffic demand. A cold/idle group only
	// samples a small rotating subset; real traffic wakes a larger bounded
	// cycle. This keeps large catch-all groups from consuming the same probe
	// budget as an actively routed regional group.
	defaultSmartActivityWindow    = 15 * time.Minute
	defaultSmartIdleProbeInterval = 30 * time.Minute
	defaultSmartColdProbeBudget   = 4
	defaultSmartActiveProbeBudget = 16
	// Status is a control-plane view, not a per-connection accounting stream.
	// Coalesce identical updates briefly so browser asset fan-out does not make
	// every dial clone the full candidate snapshot under statusAccess.
	smartStatusMinPublishInterval = 200 * time.Millisecond
	// Large provider groups use a coarse near-tie hash automatically. This is
	// deliberately internal: most users should not need to tune stickiness.
	smartCoarseAffinityThreshold = 16
)

// smartPhase makes cold-start behavior explicit.  A group is usable from the
// first successful dial/basic probe; only the later profiling and steady
// phases may make performance-driven changes.  Hard failures always fail over
// immediately regardless of phase.
type smartPhase uint32

const (
	smartPhaseCold smartPhase = iota
	smartPhaseBaseline
	smartPhaseProfiling
	smartPhaseSteady
)

func (p smartPhase) String() string {
	switch p {
	case smartPhaseBaseline:
		return "baseline"
	case smartPhaseProfiling:
		return "profiling"
	case smartPhaseSteady:
		return "steady"
	default:
		return "cold"
	}
}

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
	identity             string
	probeKey             string
	policyID             uint64
	weight               nodeweight.Match
	status               adapter.SmartCandidateStatus
	profile              smartTrafficProfile
	estimate             smartEstimate
	scoreEstimate        smartEstimate
	eligible             bool
	passiveThroughputLow bool
}

// smartCandidateMetadata is built when providers refresh, not while ranking
// each new connection. Endpoint identity, probe key, policy id and weight
// rules are immutable until the candidate catalog changes.
type smartCandidateMetadata struct {
	identity  string
	profileID string
	probeKey  string
	policyID  uint64
	weight    nodeweight.Match
}

// smartEndpointID returns the safe, stable identity exposed by Smart status
// and switch audit records. Structured provider identities are already
// content-addressed (endpoint:<sha256>); legacy/static candidates use the
// policy hash so a raw tag, URL, or credential can never leak through the API.
func smartEndpointID(identity string, policyID uint64) string {
	if strings.HasPrefix(identity, "endpoint:") {
		return identity
	}
	if policyID != 0 {
		return "policy:" + strconv.FormatUint(policyID, 16)
	}
	return ""
}

func (s *Smart) buildCandidateMetadata(tag, identity string) smartCandidateMetadata {
	metadata := smartCandidateMetadata{
		identity:  identity,
		profileID: tag,
		probeKey:  smartProbeKey(identity, s.probeURL, s.probeTimeout),
		weight:    s.nodeWeights.Explain(tag),
	}
	if identity != "" && identity != tag {
		metadata.profileID = "endpoint:" + identity
	}
	if identity != "" {
		metadata.policyID = smartPolicyID(identity)
	}
	return metadata
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

	access                 sync.RWMutex
	candidates             []adapter.Outbound
	candidateByTag         map[string]adapter.Outbound
	candidateMetadataByTag map[string]smartCandidateMetadata
	control                *smartControlState
	lastSelected           map[string]string
	lastSelectedAt         map[string]time.Time
	affinity               map[string]smartAffinity
	switchChallenges       map[string]smartSwitchChallenge
	performanceCooldown    map[string]time.Time
	halfOpen               map[string]struct{}
	latest                 common.TypedValue[adapter.Outbound]
	fingerprint            atomic.Pointer[smartFingerprintCache]
	fingerprintLock        sync.Mutex

	statusAccess       sync.RWMutex
	status             adapter.SmartGroupStatus
	statusContexts     map[string]adapter.SmartContextStatus
	statusContextOrder []string
	statusLastAt       time.Time
	statusLastContext  string
	statusLastSelected string
	statusLastReason   string
	statusLastPhase    string

	store                      *smartStore
	policyBackend              smartPolicyBackend
	policyBackendAccess        sync.RWMutex
	probeURL                   string
	probeInterval              time.Duration
	probeCycleTimeout          time.Duration
	probeTimeout               time.Duration
	probeConcurrency           int
	maxAttempts                int
	attemptTimeout             time.Duration
	establishedStallTimeout    time.Duration
	siteStickiness             time.Duration
	switchConfirm              time.Duration
	switchConfirmSamples       int
	switchCooldown             time.Duration
	switchMargin               float64
	switchMinImprovement       time.Duration
	exploration                float64
	minSamples                 int
	passiveThroughputFloorBPS  uint64
	passiveThroughputSamples   int
	halfLife                   time.Duration
	breakerFailures            int
	breakerCooldown            time.Duration
	historyRetention           time.Duration
	maxHistoryEntries          int
	interruptGroup             *interrupt.Group
	interruptExternal          bool
	interruptMode              string
	interruptIdle              time.Duration
	interruptLongAge           time.Duration
	interruptGrace             time.Duration
	switchesTotal              atomic.Uint64
	performanceSwitches        atomic.Uint64
	failureFailovers           atomic.Uint64
	coldStarts                 atomic.Uint64
	switchAuditAccess          sync.Mutex
	switchAudit                []adapter.SmartSwitchAudit
	switchesForceAll           atomic.Uint64
	switchesSelective          atomic.Uint64
	connectionsInterrupted     atomic.Uint64
	connectionsKept            atomic.Uint64
	streamFailureWakes         atomic.Uint64
	recoveryProbeUntilUnixNano atomic.Int64
	probing                    atomic.Bool
	probeCursor                atomic.Uint64
	phase                      atomic.Uint32
	phaseInitialized           atomic.Bool
	successfulProbeCycles      atomic.Uint32
	lastActivityUnixNano       atomic.Int64
	closing                    atomic.Bool
	cancel                     context.CancelFunc
	worker                     sync.WaitGroup
	lifecycleAccess            sync.Mutex
	postStarted                bool
	retired                    bool
	workerStarted              bool
	probeRegistry              *smartProbeRegistry
	releaseProbeRegistry       func()
	probeStartupDelay          time.Duration
	probeNow                   chan struct{}
	families                   *trafficfamily.Resolver
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
	probeURL := normalizeSmartProbeURL(options.URL)
	if probeURL != options.URL && logger != nil {
		logger.Warn("smart probe URL uses a recursive DNS hostname; using bootstrap-safe probe endpoint")
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
	establishedStallTimeout := time.Duration(options.EstablishedStallTimeout)
	if establishedStallTimeout <= 0 {
		establishedStallTimeout = defaultSmartEstablishedStallTimeout
	}
	if establishedStallTimeout < minSmartEstablishedStallTimeout || establishedStallTimeout > maxSmartEstablishedStallTimeout {
		return nil, E.New("smart established_stall_timeout must be between 5s and 2m")
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

		candidateByTag:         make(map[string]adapter.Outbound),
		candidateMetadataByTag: make(map[string]smartCandidateMetadata),
		control:                &smartControlState{},
		lastSelected:           make(map[string]string),
		lastSelectedAt:         make(map[string]time.Time),
		affinity:               make(map[string]smartAffinity),
		switchChallenges:       make(map[string]smartSwitchChallenge),
		performanceCooldown:    make(map[string]time.Time),
		halfOpen:               make(map[string]struct{}),
		store:                  store,
		policyBackend:          policyBackend,

		probeURL:                  probeURL,
		probeInterval:             probeInterval,
		probeCycleTimeout:         probeCycleTimeout,
		probeTimeout:              probeTimeout,
		probeConcurrency:          probeConcurrency,
		maxAttempts:               maxAttempts,
		attemptTimeout:            attemptTimeout,
		establishedStallTimeout:   establishedStallTimeout,
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

// normalizeSmartProbeURL prevents a cold-start dependency cycle. The legacy
// gstatic probe is commonly resolved by dns-proxy through Smart itself; when
// the cache is cold that leaves both the resolver and the health worker waiting
// on one another. Only the legacy/default target is rewritten. Explicit
// operator targets remain untouched.
func normalizeSmartProbeURL(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return defaultSmartProbeURL
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || !strings.EqualFold(parsed.Hostname(), "www.gstatic.com") {
		return trimmed
	}
	return defaultSmartProbeURL
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
	clear(s.lastSelectedAt)
	clear(s.affinity)
	clear(s.switchChallenges)
	clear(s.performanceCooldown)
	clear(s.halfOpen)
	s.candidates = nil
	s.candidateByTag = make(map[string]adapter.Outbound)
	s.candidateMetadataByTag = nil
	s.lastSelected = make(map[string]string)
	s.lastSelectedAt = make(map[string]time.Time)
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
	s.closePolicyBackend()
	if s.releaseProbeRegistry != nil {
		s.releaseProbeRegistry()
		s.releaseProbeRegistry = nil
	}
	return nil
}

// policyBackendEnabled snapshots only whether the optional policy kernel is
// available. Calls into the backend itself must use the helpers below so
// Smart.Close cannot destroy a Zig engine while another goroutine is inside
// its C ABI.
func (s *Smart) policyBackendEnabled() bool {
	s.policyBackendAccess.RLock()
	enabled := s.policyBackend != nil
	s.policyBackendAccess.RUnlock()
	return enabled
}

func (s *Smart) resetPolicyBackend() {
	s.policyBackendAccess.RLock()
	if s.policyBackend != nil {
		s.policyBackend.Reset()
	}
	s.policyBackendAccess.RUnlock()
}

func (s *Smart) closePolicyBackend() {
	s.policyBackendAccess.Lock()
	if s.policyBackend != nil {
		s.policyBackend.Close()
		s.policyBackend = nil
	}
	s.policyBackendAccess.Unlock()
}

func (s *Smart) observePolicyBackend(key string, id uint64, success bool, elapsed time.Duration, now time.Time) bool {
	s.policyBackendAccess.RLock()
	if s.policyBackend == nil {
		s.policyBackendAccess.RUnlock()
		return false
	}
	s.policyBackend.Observe(key, id, success, elapsed, now)
	s.policyBackendAccess.RUnlock()
	return true
}

func (s *Smart) choosePolicyBackend(key string, candidates []smartPolicyCandidate, profile smartTrafficProfile, now time.Time) (smartPolicyDecision, bool) {
	s.policyBackendAccess.RLock()
	if s.policyBackend == nil {
		s.policyBackendAccess.RUnlock()
		return smartPolicyDecision{}, false
	}
	decision := s.policyBackend.Choose(key, candidates, profile, now)
	s.policyBackendAccess.RUnlock()
	return decision, true
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

func (s *Smart) currentPhase() smartPhase {
	if s == nil {
		return smartPhaseCold
	}
	return smartPhase(s.phase.Load())
}

func (s *Smart) setPhase(phase smartPhase) {
	if s == nil {
		return
	}
	for {
		current := smartPhase(s.phase.Load())
		if phase <= current {
			return
		}
		if s.phase.CompareAndSwap(uint32(current), uint32(phase)) {
			return
		}
	}
}

func (s *Smart) noteProbeCycle(successes int) {
	if s == nil || successes <= 0 || s.closing.Load() {
		return
	}
	// The first successful basic probe publishes a usable baseline immediately.
	// A second completed cycle enters profiling; the steady phase is reached
	// after the third cycle or earlier through real-traffic samples below.
	successful := s.successfulProbeCycles.Add(1)
	switch {
	case successful >= 3:
		s.setPhase(smartPhaseSteady)
	case successful >= 2:
		s.setPhase(smartPhaseProfiling)
	default:
		s.setPhase(smartPhaseBaseline)
	}
}

func (s *Smart) performanceSwitchAllowed() bool {
	// Embedded users of Smart (and unit-test fixtures) may not run the worker.
	// Preserve the historical reference-policy behavior for those callers; the
	// production lifecycle always starts in cold phase before PostStart probes.
	if !s.phaseInitialized.Load() {
		return true
	}
	return s.currentPhase() >= smartPhaseProfiling
}

// coarseAffinityIndex provides a coarse mihomo-style stickiness automatically
// for large provider groups without adding another user-facing knob. Only
// candidates within the configured relative margin of the best eligible score
// participate; a stable hash then picks one of that near-tied set. Small groups
// continue to use the more precise service/site affinity path.
func (s *Smart) coarseAffinityIndex(ranks []smartRank, key string) int {
	if s == nil || len(ranks) < smartCoarseAffinityThreshold || key == "" {
		return -1
	}
	best := -1
	for index := range ranks {
		if ranks[index].eligible {
			best = index
			break
		}
	}
	if best < 0 {
		return -1
	}
	bestScore := ranks[best].status.Score
	threshold := bestScore * (1 + s.switchMargin)
	if bestScore == 0 {
		threshold = 0.05
	}
	pool := make([]int, 0, len(ranks))
	for index := range ranks {
		if ranks[index].eligible && ranks[index].status.Score <= threshold {
			pool = append(pool, index)
		}
	}
	if len(pool) == 0 {
		return best
	}
	hash := fnv.New64a()
	_, _ = hash.Write([]byte(key))
	return pool[hash.Sum64()%uint64(len(pool))]
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
	s.phaseInitialized.Store(true)
	s.phase.Store(uint32(smartPhaseCold))
	s.successfulProbeCycles.Store(0)
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
	// The first real request after a restart must not promote a cold group to
	// the active budget. noteTrafficActivity records activity before waking the
	// worker, so checking activeAt alone turns the first request into a large
	// five-group probe burst and competes with the request being served. Keep
	// the cold budget until the group has completed at least one baseline cycle;
	// profiling/steady phases can use the larger activity-driven budget.
	if s.currentPhase() <= smartPhaseBaseline {
		return defaultSmartColdProbeBudget
	}
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
	contextSelected := ""
	if metadata != nil {
		transport := N.NetworkName(metadata.Network)
		_, siteKey := resolveSmartSiteIdentity(s.families, metadata, metadata.Destination)
		if transport != "" && siteKey != "" {
			contextKey := smartSelectionKey(s.networkFingerprint(), siteKey, transport)
			s.access.RLock()
			contextSelected = s.lastSelected[contextKey]
			s.access.RUnlock()
		}
	}
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
	if selected := pick(contextSelected); selected != nil {
		return selected
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
	if len(s.statusContexts) > 0 {
		status.Contexts = make([]adapter.SmartContextStatus, 0, len(s.statusContexts))
		for _, key := range s.statusContextOrder {
			if contextStatus, loaded := s.statusContexts[key]; loaded {
				status.Contexts = append(status.Contexts, cloneSmartContextStatus(contextStatus))
			}
		}
	}
	s.switchAuditAccess.Lock()
	status.RecentSwitches = append([]adapter.SmartSwitchAudit(nil), s.switchAudit...)
	s.switchAuditAccess.Unlock()
	return status
}

func cloneSmartContextStatus(source adapter.SmartContextStatus) adapter.SmartContextStatus {
	result := source
	result.StateCounts = cloneSmartStateCounts(source.StateCounts)
	result.Candidates = append([]adapter.SmartCandidateStatus(nil), source.Candidates...)
	return result
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
	s.resetPolicyBackend()
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
	s.resetPolicyBackend()
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
	defer func() { ranking.Release() }()
	ranks := ranking.ranks
	if len(ranks) == 0 {
		return nil, E.New("smart group is warming: no supported candidate")
	}
	if !hasEligibleSmartRank(ranks) {
		// All circuits being open is an outage state, not a reason to strand the
		// group indefinitely. Run a small, single-flight half-open URLTest-style
		// recovery sample, then rank again if any endpoint proves reachable.
		if s.recoverOpenCandidates(ctx, ranking.candidates, transport) {
			ranking.Release()
			ranking, networkKey, siteKey, siteDisplay = s.rankPooled(ctx, transport, destination)
			ranks = ranking.ranks
		}
		if !hasEligibleSmartRank(ranks) {
			return nil, E.New("smart group has no service-reachable candidate")
		}
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
		observedStartedAt := time.Now().Add(-result.elapsed)
		return newSmartObservedConnWithRetransmit(conn, observedStartedAt, func(firstByte time.Duration) {
			s.store.observeFirstByte(time.Now(), networkKey, siteKey, s.candidateProfileID(candidate.Tag()), transport, firstByte)
		}, func(bytes int64, duration time.Duration) {
			s.store.observeThroughput(time.Now(), networkKey, siteKey, s.candidateProfileID(candidate.Tag()), transport, bytes, duration)
		}, func(ratio float64) {
			s.store.observeRetransmit(time.Now(), networkKey, siteKey, s.candidateProfileID(candidate.Tag()), transport, ratio)
		}, func() {
			// A stream can become unusable after DialContext succeeds (for
			// example a stale multiplex session, a reset upstream socket, or
			// a bounded first-response stall). Record the failure against this
			// network/site/transport profile and wake the shared probe. The
			// callback is coalesced once per connection by smartObservedConn.
			s.streamFailureWakes.Add(1)
			s.observeDial(time.Now(), networkKey, siteKey, candidate.Tag(), transport, false, time.Since(observedStartedAt))
			s.clearBrokenPin(candidate.Tag(), networkKey, siteKey, transport)
			s.requestProbe()
		}, s.establishedStallTimeout), nil
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

// recoverOpenCandidates is the outage escape hatch for the staged selector.
// Once every candidate is circuit-open, waiting for the ordinary probe cadence
// would strand new connections. A short, rotating half-open sample instead
// revalidates a bounded subset; one success immediately closes that endpoint's
// circuit and lets the normal health-tier ranking choose it as primary. The
// registry keeps the sample single-flight across Smart groups.
func (s *Smart) recoverOpenCandidates(ctx context.Context, candidates []adapter.Outbound, transport string) bool {
	if s == nil || ctx.Err() != nil || s.closing.Load() || len(candidates) == 0 {
		return false
	}
	now := time.Now()
	next := s.recoveryProbeUntilUnixNano.Load()
	if next > now.UnixNano() || !s.recoveryProbeUntilUnixNano.CompareAndSwap(next, now.Add(defaultSmartRecoveryProbeCooldown).UnixNano()) {
		return false
	}
	eligible := make([]adapter.Outbound, 0, len(candidates))
	for _, candidate := range candidates {
		if common.Contains(candidate.Network(), transport) {
			eligible = append(eligible, candidate)
		}
	}
	if len(eligible) == 0 {
		return false
	}
	budget := max(defaultSmartColdProbeBudget, max(s.maxAttempts, 1))
	if budget > 8 {
		budget = 8
	}
	if len(eligible) > budget {
		start := int(s.probeCursor.Add(uint64(budget))-uint64(budget)) % len(eligible)
		eligible = append(eligible[start:], eligible[:start]...)
		eligible = eligible[:budget]
	}
	probeTimeout := defaultSmartRecoveryProbeTimeout
	if s.probeTimeout > 0 && s.probeTimeout < probeTimeout {
		probeTimeout = s.probeTimeout
	}
	type recoveryResult struct {
		candidate adapter.Outbound
		measured  time.Duration
		err       error
		performed bool
	}
	results := make(chan recoveryResult, len(eligible))
	jobs := make(chan adapter.Outbound)
	workerCount := min(max(s.probeConcurrency, 1), len(eligible))
	var workers sync.WaitGroup
	for range workerCount {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for candidate := range jobs {
				probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
				startedAt := time.Now()
				var (
					err       error
					measured  time.Duration
					performed bool
				)
				if s.probeRegistry != nil {
					s.access.RLock()
					metadata := s.candidateMetadataByTag[candidate.Tag()]
					s.access.RUnlock()
					identity := metadata.identity
					if identity == "" {
						identity = candidate.Tag()
					}
					key := metadata.probeKey
					if transport == N.NetworkUDP {
						key = smartProbeKey(identity, "udp://dns-health", probeTimeout)
					} else if key == "" {
						key = smartProbeKey(identity, s.probeURL, probeTimeout)
					}
					var delay uint16
					delay, err = s.probeRegistry.runRecoveryForEndpoint(probeCtx, identity, key, probeTimeout, s.probeInterval, func(probeContext context.Context) (uint16, error) {
						performed = true
						if transport == N.NetworkUDP {
							return 0, runSmartUDPHealthProbe(probeContext, candidate)
						}
						return s.probeRegistry.probe(probeContext, s.probeURL, candidate)
					})
					if transport == N.NetworkUDP {
						measured = time.Since(startedAt)
					} else if err == nil {
						measured = time.Duration(delay) * time.Millisecond
					}
				} else if transport == N.NetworkUDP {
					performed = true
					err = runSmartUDPHealthProbe(probeCtx, candidate)
					measured = time.Since(startedAt)
				} else {
					performed = true
					var delay uint16
					delay, err = urltest.URLTest(probeCtx, s.probeURL, candidate)
					if err == nil {
						measured = time.Duration(delay) * time.Millisecond
					}
				}
				cancel()
				if measured <= 0 {
					measured = time.Since(startedAt)
				}
				results <- recoveryResult{candidate: candidate, measured: measured, err: err, performed: performed}
			}
		}()
	}
dispatch:
	for _, candidate := range eligible {
		select {
		case jobs <- candidate:
		case <-ctx.Done():
			break dispatch
		}
	}
	close(jobs)
	workers.Wait()
	close(results)
	networkKey := s.networkFingerprint()
	successes := 0
	for result := range results {
		if !result.performed {
			// A waiter still needs one local success observation to recover its
			// own store, but must not duplicate a shared failure penalty.
			if result.err != nil {
				continue
			}
		}
		if result.err == nil {
			successes++
			s.observeDial(time.Now(), networkKey, "", result.candidate.Tag(), transport, true, result.measured)
		} else if result.performed {
			s.observeDial(time.Now(), networkKey, "", result.candidate.Tag(), transport, false, result.measured)
		}
	}
	if successes > 0 {
		s.noteProbeCycle(successes)
		return true
	}
	return false
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
		if s.currentPhase() > smartPhaseBaseline && started == 1 && attempts[0].rank.status.State == "healthy" &&
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
	if s.currentPhase() <= smartPhaseBaseline {
		// During cold/baseline startup the first candidate is often only an
		// unprofiled guess. Start the backup after 250ms so first use is fast;
		// once profiling is established the longer delay protects keep-alive
		// paths from needless parallel dials.
		return minSmartHedgeDelay
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
	defer func() { ranking.Release() }()
	ranks := ranking.ranks
	if len(ranks) == 0 {
		return nil, E.New("smart group is warming: no supported candidate")
	}
	if !hasEligibleSmartRank(ranks) {
		if s.recoverOpenCandidates(ctx, ranking.candidates, transport) {
			ranking.Release()
			ranking, networkKey, siteKey, siteDisplay = s.rankPooled(ctx, transport, destination)
			ranks = ranking.ranks
		}
		if !hasEligibleSmartRank(ranks) {
			return nil, E.New("smart group has no service-reachable UDP candidate")
		}
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
		observed := newSmartObservedPacketConnWithWatchdog(conn, startedAt, smartUDPExpectsResponse(destination), s.establishedStallTimeout, func(flowElapsed time.Duration) {
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

// PerformUpdateCheck is the non-blocking hook used by the Clash API after a
// manual delay test. Smart owns its probe worker, so the API must only wake a
// bounded cycle instead of starting a second probe goroutine or mutating
// selection state from the HTTP handler.
func (s *Smart) PerformUpdateCheck() {
	if s.closing.Load() {
		return
	}
	s.requestProbe()
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
	metadataByTag := s.candidateMetadataByTag
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
		// performed is false for a registry cache hit.  Cached answers are
		// usable for the caller, but must not be counted as fresh evidence.
		performed bool
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
				metadata, ok := metadataByTag[candidate.Tag()]
				if !ok {
					metadata = s.buildCandidateMetadata(candidate.Tag(), "")
				}
				key := metadata.probeKey
				var delay uint16
				var err error
				performed := false
				if s.probeRegistry != nil {
					// Admission is process-wide and may legitimately wait behind
					// another group. Apply the per-node timeout only after a slot is
					// acquired inside the registry; otherwise a healthy node can be
					// mislabeled merely because the shared queue took five seconds.
					delay, err, performed = s.probeRegistry.runWithMetaForEndpoint(ctx, metadata.identity, key, s.probeURL, s.probeTimeout, s.probeInterval, candidate)
				} else {
					// Test/embedded constructors created before the shared registry
					// contract retain the stock direct probe path.
					testCtx, cancel := context.WithTimeout(ctx, s.probeTimeout)
					delay, err = urltest.URLTest(testCtx, s.probeURL, candidate)
					cancel()
					performed = true
				}
				penalize := err != nil && !errors.Is(err, errSharedSmartProbeDeferred) && ctx.Err() == nil && !s.closing.Load()
				results <- probeResult{candidate: candidate, delay: delay, err: err, penalize: penalize, performed: performed}
			}
		}()
	}
	type probeSummary struct {
		collected []probeResult
		successes int
		performed int
	}
	networkKey := s.networkFingerprint()
	summaryDone := make(chan probeSummary, 1)
	go func() {
		summary := probeSummary{collected: make([]probeResult, 0, len(candidates))}
		published := false
		for probe := range results {
			summary.collected = append(summary.collected, probe)
			if probe.performed {
				summary.performed++
			}
			if probe.err != nil {
				continue
			}
			result[probe.candidate.Tag()] = probe.delay
			if !probe.performed {
				continue
			}
			summary.successes++
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
	if ctx.Err() == nil && !s.closing.Load() {
		// TCP probes establish reachability; a small, serialized UDP DNS sample
		// establishes that the same candidate can carry transactional datagrams.
		// Keep this separate from the TCP result map so URLTest callers retain
		// their historical latency contract while UDP evidence enters its own
		// profile and cannot poison TCP ranking.
		s.probeUDPWithBudget(ctx, candidates, budget)
	}
	if s.closing.Load() {
		// Shutdown: skip store mutations so Close can clear maps safely.  A
		// probe-cycle deadline is different: completed observations remain
		// valuable and must be committed so inactive/large groups eventually
		// build a baseline over multiple bounded cycles.
		return result, ctx.Err()
	}
	commonFailure := summary.performed > 1 && summary.successes == 0
	for _, probe := range summary.collected {
		if probe.err != nil && probe.penalize && probe.performed && !commonFailure {
			metadata, ok := metadataByTag[probe.candidate.Tag()]
			if !ok {
				metadata = s.buildCandidateMetadata(probe.candidate.Tag(), "")
			}
			if s.probeRegistry == nil || s.probeRegistry.dead(metadata.probeKey) {
				s.observeDial(time.Now(), networkKey, "", probe.candidate.Tag(), N.NetworkTCP, false, s.probeTimeout)
			}
		}
	}
	if summary.successes > 0 {
		s.noteProbeCycle(summary.successes)
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

type smartUDPProbeResult struct {
	candidate adapter.Outbound
	elapsed   time.Duration
	err       error
	performed bool
}

var smartUDPProbeTargets = [...]M.Socksaddr{
	M.ParseSocksaddr("1.1.1.1:53"),
	M.ParseSocksaddr("8.8.8.8:53"),
}

func (s *Smart) probeUDPWithBudget(ctx context.Context, candidates []adapter.Outbound, budget int) {
	if ctx.Err() != nil || s.closing.Load() || len(candidates) == 0 {
		return
	}
	udpCandidates := make([]adapter.Outbound, 0, len(candidates))
	for _, candidate := range candidates {
		if common.Contains(candidate.Network(), N.NetworkUDP) {
			udpCandidates = append(udpCandidates, candidate)
		}
	}
	if len(udpCandidates) == 0 {
		return
	}
	if budget <= 0 || budget > defaultSmartUDPProbeTargetCount {
		budget = defaultSmartUDPProbeTargetCount
	}
	if budget > len(udpCandidates) {
		budget = len(udpCandidates)
	}
	udpCandidates = udpCandidates[:budget]
	results := make(chan smartUDPProbeResult, len(udpCandidates))
	jobs := make(chan adapter.Outbound)
	var waitGroup sync.WaitGroup
	// One UDP probe at a time is intentional: the test is a reachability gate,
	// not a throughput benchmark, and this keeps a cold five-region start from
	// creating a burst of NAT sessions.
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		for candidate := range jobs {
			probeCtx, cancel := context.WithTimeout(ctx, defaultSmartUDPProbeTimeout)
			startedAt := time.Now()
			performed := false
			var err error
			if s.probeRegistry != nil {
				s.access.RLock()
				metadata := s.candidateMetadataByTag[candidate.Tag()]
				s.access.RUnlock()
				identity := metadata.identity
				if identity == "" {
					identity = candidate.Tag()
				}
				probeTimeout := s.probeTimeout
				if probeTimeout <= 0 {
					probeTimeout = defaultSmartUDPProbeTimeout
				}
				key := smartProbeKey(identity, "udp://dns-health", probeTimeout)
				_, err = s.probeRegistry.runProbeForEndpoint(probeCtx, identity, key, probeTimeout, s.probeInterval, func(probeContext context.Context) (uint16, error) {
					performed = true
					return 0, runSmartUDPHealthProbe(probeContext, candidate)
				})
			} else {
				performed = true
				err = runSmartUDPHealthProbe(probeCtx, candidate)
			}
			cancel()
			results <- smartUDPProbeResult{candidate: candidate, elapsed: time.Since(startedAt), err: err, performed: performed}
		}
	}()
dispatch:
	for _, candidate := range udpCandidates {
		select {
		case jobs <- candidate:
		case <-ctx.Done():
			break dispatch
		}
	}
	close(jobs)
	waitGroup.Wait()
	close(results)

	networkKey := s.networkFingerprint()
	completed := make([]smartUDPProbeResult, 0, len(udpCandidates))
	for result := range results {
		if s.closing.Load() || ctx.Err() != nil {
			return
		}
		completed = append(completed, result)
		if result.err == nil {
			// A shared successful probe is valid evidence for every Smart group
			// waiting on the same canonical endpoint.  Record it locally even when
			// this caller was not the registry owner; only failures are owner-only
			// so a single outage does not multiply breaker penalties.
			s.observeDial(time.Now(), networkKey, "__udp_probe__", result.candidate.Tag(), N.NetworkUDP, true, result.elapsed)
		}
	}
	for _, result := range completed {
		if result.err != nil && result.performed {
			// Probe failures are advisory evidence. They are recorded in a
			// dedicated low-weight site so a filtered public DNS target cannot
			// hard-open the endpoint, while repeated real UDP failures still use
			// the normal transport breaker.
			s.observeDial(time.Now(), networkKey, "__udp_probe__", result.candidate.Tag(), N.NetworkUDP, false, result.elapsed)
		}
	}
}

func runSmartUDPHealthProbe(ctx context.Context, candidate adapter.Outbound) error {
	query, id, question, err := buildSmartDNSHealthQuery()
	if err != nil {
		return err
	}
	for _, target := range smartUDPProbeTargets {
		if err := ctx.Err(); err != nil {
			return err
		}
		packetConn, err := candidate.ListenPacket(ctx, target)
		if err != nil {
			continue
		}
		deadline := time.Now().Add(defaultSmartUDPProbeTimeout)
		if contextDeadline, loaded := ctx.Deadline(); loaded && contextDeadline.Before(deadline) {
			deadline = contextDeadline
		}
		if err = packetConn.SetDeadline(deadline); err == nil {
			_, err = packetConn.WriteTo(query, target.UDPAddr())
		}
		if err == nil {
			response := make([]byte, 2048)
			var count int
			count, _, err = packetConn.ReadFrom(response)
			if err == nil {
				err = validateSmartDNSHealthResponse(response[:count], id, question)
			}
		}
		_ = packetConn.Close()
		if err == nil {
			return nil
		}
	}
	return errors.New("smart UDP DNS health probe failed")
}

func buildSmartDNSHealthQuery() ([]byte, uint16, dnsmessage.Question, error) {
	var randomID [2]byte
	if _, err := rand.Read(randomID[:]); err != nil {
		return nil, 0, dnsmessage.Question{}, err
	}
	id := binary.BigEndian.Uint16(randomID[:])
	name, err := dnsmessage.NewName("example.com.")
	if err != nil {
		return nil, 0, dnsmessage.Question{}, err
	}
	question := dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	if err = builder.StartQuestions(); err != nil {
		return nil, 0, dnsmessage.Question{}, err
	}
	if err = builder.Question(question); err != nil {
		return nil, 0, dnsmessage.Question{}, err
	}
	message, err := builder.Finish()
	return message, id, question, err
}

func validateSmartDNSHealthResponse(message []byte, id uint16, expected dnsmessage.Question) error {
	var parser dnsmessage.Parser
	header, err := parser.Start(message)
	if err != nil {
		return err
	}
	if !header.Response || header.ID != id || header.RCode != dnsmessage.RCodeSuccess {
		return errors.New("unexpected smart UDP DNS response")
	}
	question, err := parser.Question()
	if err != nil {
		return err
	}
	if question != expected {
		return errors.New("smart UDP DNS response question mismatch")
	}
	return nil
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
	// The backend observes the canonical endpoint identity. Metadata is read
	// under the catalog lock so provider refresh cannot race this callback.
	s.access.RLock()
	metadata := s.candidateMetadataByTag[candidate]
	s.access.RUnlock()
	if metadata.identity != "" {
		s.observePolicyBackend(smartSelectionKey(network, site, transport), metadata.policyID, success, elapsed, now)
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
	metadata := s.candidateMetadataByTag[candidate]
	s.access.RUnlock()
	if metadata.profileID == "" {
		return candidate
	}
	return metadata.profileID
}

func (s *Smart) rankPooled(ctx context.Context, transport string, destination M.Socksaddr) (*smartRanking, string, string, string) {
	now := time.Now()
	pinned, temporary, _, _ := s.controlSnapshot(now)
	networkKey := s.networkFingerprint()
	siteDisplay, siteKey := s.resolveSmartSiteIdentity(adapter.ContextFrom(ctx), destination)
	s.access.RLock()
	ranking := acquireSmartRanking(len(s.candidates))
	ranking.candidates = append(ranking.candidates, s.candidates...)
	metadataByTag := s.candidateMetadataByTag
	selectionKey := smartSelectionKey(networkKey, siteKey, transport)
	lastSelected := s.lastSelected[selectionKey]
	if selectedAt := s.lastSelectedAt[selectionKey]; lastSelected != "" && !selectedAt.IsZero() && s.siteStickiness > 0 && now.Sub(selectedAt) > s.siteStickiness {
		lastSelected = ""
	}
	affinity := s.affinity[networkKey+"\x00"+siteKey+"\x00"+transport]
	s.access.RUnlock()

	totalSamples := 0.0
	var policyCandidates []smartPolicyCandidate
	var policyIDs map[uint64]struct{}
	usePolicyBackend := s.policyBackendEnabled()
	if usePolicyBackend {
		policyCandidates = make([]smartPolicyCandidate, 0, len(ranking.candidates))
		policyIDs = make(map[uint64]struct{}, len(ranking.candidates))
	}
	profile := smartProfileInteractive
	if transport == N.NetworkUDP {
		profile = smartProfileUDP
	}
	for _, candidate := range ranking.candidates {
		if !common.Contains(candidate.Network(), transport) {
			continue
		}
		metadata, ok := metadataByTag[candidate.Tag()]
		if !ok {
			metadata = s.buildCandidateMetadata(candidate.Tag(), "")
		}
		estimate := s.store.estimate(now, networkKey, siteKey, metadata.profileID, transport, s.minSamples)
		scoreEstimate := estimate
		if transport == N.NetworkTCP && estimate.HasRetransmit {
			// Surge models TCP loss as an additive latency penalty. Keep the raw
			// ratio visible in status, but feed the same bounded penalty to both
			// host and Zig scoring paths so the policy backend cannot ignore it.
			penalty := smartRetransmitPenaltyMS(estimate.RetransmitRatio)
			scoreEstimate.ConnectMS += penalty
			scoreEstimate.ConnectP95MS += penalty
			scoreEstimate.FirstByteMS += penalty
			scoreEstimate.FirstByteP95MS += penalty
		}
		sharedProbeDead := false
		if s.probeRegistry != nil && common.Contains(candidate.Network(), N.NetworkTCP) {
			sharedProbeDead = s.probeRegistry.dead(metadata.probeKey)
		}
		if sharedProbeDead {
			estimate.State = "open"
		}
		totalSamples += estimate.Samples
		profileThroughputSamples := estimate.ThroughputSamples
		if siteKey != "" {
			profileThroughputSamples = estimate.LocalThroughputSamples
		}
		if profile == smartProfileInteractive && profileThroughputSamples >= 2 {
			profile = smartProfileBulk
		}
		ranking.ranks = append(ranking.ranks, smartRank{
			outbound:      candidate,
			identity:      metadata.identity,
			probeKey:      metadata.probeKey,
			policyID:      metadata.policyID,
			weight:        metadata.weight,
			estimate:      estimate,
			scoreEstimate: scoreEstimate,
			// Hard health gates run before weights and soft score. A circuit-open
			// endpoint must never become eligible merely because it has a large
			// configured weight.
			eligible: estimate.State != "open",
			status: adapter.SmartCandidateStatus{
				Tag:             candidate.Tag(),
				EndpointID:      smartEndpointID(metadata.identity, metadata.policyID),
				State:           estimate.State,
				Reliability:     estimate.Reliability,
				ConnectMS:       estimate.ConnectMS,
				ConnectP95MS:    estimate.ConnectP95MS,
				FirstByteMS:     estimate.FirstByteMS,
				FirstByteP95MS:  estimate.FirstByteP95MS,
				ThroughputBPS:   estimate.ThroughputBPS,
				RetransmitRatio: estimate.RetransmitRatio,
				Samples:         estimate.Samples,
			},
		})
		if usePolicyBackend && metadata.identity != "" {
			// Several provider lines can describe one endpoint.  Let the policy
			// kernel see one candidate so suffix-renamed duplicates cannot create
			// contradictory state; the host still keeps all lines for fallback.
			if _, exists := policyIDs[metadata.policyID]; !exists {
				policyIDs[metadata.policyID] = struct{}{}
				policyCandidates = append(policyCandidates, smartPolicyCandidate{
					ID: metadata.policyID, Reliability: scoreEstimate.Reliability, ConnectMS: smartConnectScoreMS(scoreEstimate),
					FirstByteMS: smartFirstByteScoreMS(scoreEstimate), JitterMS: scoreEstimate.JitterMS,
					Throughput: scoreEstimate.ThroughputBPS, Samples: scoreEstimate.Samples,
					Weight: metadata.weight.Weight,
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
			policyID := ranking.ranks[index].policyID
			for policyIndex := range policyCandidates {
				if policyCandidates[policyIndex].ID == policyID {
					policyCandidates[policyIndex].State = smartPolicyState("open")
					policyCandidates[policyIndex].Eligible = false
				}
			}
		}
	}
	for index := range ranking.ranks {
		weightMatch := ranking.ranks[index].weight
		weight := weightMatch.Weight
		ranking.ranks[index].profile = profile
		ranking.ranks[index].status.Score = smartScoreForProfile(ranking.ranks[index].scoreEstimate, profile, s.exploration, totalSamples) / weight
		ranking.ranks[index].status.Weight = weight
		ranking.ranks[index].status.WeightRule = weightMatch.Rule
		ranking.ranks[index].status.WeightExact = weightMatch.Exact
		if !ranking.ranks[index].passiveThroughputLow {
			ranking.ranks[index].status.Reason = smartEstimateReason(ranking.ranks[index].estimate)
		}
		ranking.ranks[index].estimate = smartEstimate{}
		ranking.ranks[index].scoreEstimate = smartEstimate{}
	}
	sort.SliceStable(ranking.ranks, func(i, j int) bool {
		if ranking.ranks[i].eligible != ranking.ranks[j].eligible {
			return ranking.ranks[i].eligible
		}
		leftTier := smartHealthTier(ranking.ranks[i].status.State)
		rightTier := smartHealthTier(ranking.ranks[j].status.State)
		if leftTier != rightTier {
			return leftTier < rightTier
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
	// The portable Zig backend owns confirmation/cooldown state when enabled.
	// Do not bypass it with the host-side coarse hash; the hash is only the
	// default fallback for the reference Go policy path.
	if !usePolicyBackend && lastSelected == "" && (affinity.Candidate == "" || !affinity.ExpiresAt.After(now)) {
		if index := s.coarseAffinityIndex(ranks, networkKey+"\x00"+siteDisplay+"\x00"+transport); index >= 0 {
			ranks[index].status.Reason = "coarse affinity hash retained near-tied candidate"
			moveSmartRankFirst(ranks, index)
			s.updateStatus(networkKey, siteDisplay, transport, ranks, "coarse affinity hash")
			return ranking, networkKey, siteKey, siteDisplay
		}
	}
	if usePolicyBackend {
		decision, backendAvailable := s.choosePolicyBackend(smartSelectionKey(networkKey, siteKey, transport), policyCandidates, profile, now)
		if !backendAvailable {
			// Close can retire the optional backend while a ranking snapshot is
			// still being assembled. Fall through to the reference Go policy
			// instead of dereferencing a retired engine.
			usePolicyBackend = false
		} else {
			if decision.SelectedID != 0 {
				// Keep the currently selected provider alias when the Zig
				// decision points at the same canonical endpoint. Providers
				// commonly expose one endpoint more than once with generated
				// suffixes; selecting the first alias on every rank would make
				// the visible tag (and the dial target) oscillate on refresh.
				selectedIndex := smartRankIndexForPolicy(ranks, decision.SelectedID, lastSelected)
				if selectedIndex >= 0 {
					currentIndex := smartRankIndex(ranks, lastSelected)
					if currentIndex >= 0 && !s.performanceSwitchAllowed() && currentIndex != selectedIndex {
						ranks[currentIndex].status.Reason = "baseline retained current candidate"
						moveSmartRankFirst(ranks, currentIndex)
						s.updateStatus(networkKey, siteDisplay, transport, ranks, "baseline retained current candidate")
						return ranking, networkKey, siteKey, siteDisplay
					}
					if currentIndex >= 0 && currentIndex != selectedIndex && ranks[currentIndex].status.State != "open" && !decision.Switched {
						// A policy engine can be recreated after a context eviction or
						// provider refresh. Its first decision is then a cold estimate,
						// not a confirmed failover. Keep a healthy incumbent until the
						// backend's confirmation FSM reports Switched, while still
						// allowing hard-open candidates to fail over immediately.
						ranks[currentIndex].status.Reason = "zig policy awaiting sustained confirmation"
						moveSmartRankFirst(ranks, currentIndex)
						s.updateStatus(networkKey, siteDisplay, transport, ranks, "zig policy awaiting sustained confirmation")
						return ranking, networkKey, siteKey, siteDisplay
					}
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
	}
	bestScore := ranks[0].status.Score
	current := lastSelected
	if affinity.Candidate != "" && affinity.ExpiresAt.After(now) {
		current = affinity.Candidate
	}
	if current != "" {
		if index := smartRankIndex(ranks, current); index >= 0 && ranks[index].status.State != "open" {
			currentScore := ranks[index].status.Score
			if !s.performanceSwitchAllowed() {
				s.clearSwitchChallenge(selectionKey)
				ranks[index].status.Reason = "baseline retained current candidate"
				moveSmartRankFirst(ranks, index)
				s.updateStatus(networkKey, siteDisplay, transport, ranks, statusReason("baseline retained current candidate"))
				return ranking, networkKey, siteKey, siteDisplay
			}
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
	usePolicyBackend := s.policyBackendEnabled()
	s.access.Lock()
	s.pruneAffinityLocked(now)
	previous := s.lastSelected[key]
	if selectedAt := s.lastSelectedAt[key]; previous != "" && !selectedAt.IsZero() && s.siteStickiness > 0 && now.Sub(selectedAt) > s.siteStickiness {
		previous = ""
	}
	// Compare canonical endpoint identity before accounting for a switch. A
	// provider refresh can replace one display alias with another while the
	// underlying server is unchanged; that is not a performance or failure
	// failover and must not interrupt healthy connections.
	sameEndpoint := smartSameEndpoint(s.candidateMetadataByTag, previous, candidate.Tag())
	logicalSwitch := previous != "" && previous != candidate.Tag() && !sameEndpoint
	previousMetadata := s.candidateMetadataByTag[previous]
	currentMetadata := s.candidateMetadataByTag[candidate.Tag()]
	previousEndpointID := smartEndpointID(previousMetadata.identity, previousMetadata.policyID)
	currentEndpointID := smartEndpointID(currentMetadata.identity, currentMetadata.policyID)
	previousRank, previousFound := smartRankByTag(ranks, previous)
	currentRank, currentFound := smartRankByTag(ranks, candidate.Tag())
	failureSwitch := hadPriorFailure || (previousFound && previousRank.status.State == "open")
	// Several requests can rank concurrently and finish in a different order.
	// Do not let a late healthy completion undo a just-committed selection.
	if !usePolicyBackend && logicalSwitch && !failureSwitch {
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
	if s.lastSelectedAt == nil {
		s.lastSelectedAt = make(map[string]time.Time)
	}
	s.lastSelectedAt[key] = now
	delete(s.switchChallenges, key)
	if !usePolicyBackend && logicalSwitch && !failureSwitch {
		if s.performanceCooldown == nil {
			s.performanceCooldown = make(map[string]time.Time)
		}
		s.performanceCooldown[key] = now.Add(s.switchCooldown)
	}
	if siteKey != "" {
		s.affinity[networkKey+"\x00"+siteKey+"\x00"+transport] = smartAffinity{Candidate: candidate.Tag(), ExpiresAt: now.Add(s.siteStickiness)}
	}
	ready := 0
	minimum := max(1, s.minSamples)
	for _, rank := range ranks {
		if rank.status.Samples >= float64(minimum) {
			ready++
		}
	}
	s.access.Unlock()
	if len(ranks) > 0 && ready >= min(2, len(ranks)) {
		s.setPhase(smartPhaseSteady)
	} else if ready > 0 {
		s.setPhase(smartPhaseProfiling)
	}
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
	} else if logicalSwitch {
		if failureSwitch {
			category = "failure_failover"
			s.failureFailovers.Add(1)
			reason = "failed candidate bypassed confirmation"
		} else {
			category = "performance_switch"
			s.performanceSwitches.Add(1)
		}
		s.appendSwitchAudit(adapter.SmartSwitchAudit{
			Network:            networkKey,
			Site:               siteDisplay,
			Transport:          transport,
			Previous:           previous,
			PreviousEndpointID: previousEndpointID,
			Current:            candidate.Tag(),
			CurrentEndpointID:  currentEndpointID,
			Category:           category,
			Reason:             reason,
			PreviousState:      previousRank.status.State,
			CurrentState:       currentRank.status.State,
			PreviousScore:      previousRank.status.Score,
			CurrentScore:       currentRank.status.Score,
			OccurredAt:         now,
		})
	}
	s.updateStatusSelected(networkKey, siteDisplay, transport, ranks, candidate.Tag(), reason)
	if logicalSwitch {
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

func smartRankIndexForPolicy(ranks []smartRank, policyID uint64, preferredTag string) int {
	if policyID == 0 {
		return -1
	}
	if preferredTag != "" {
		if index := smartRankIndex(ranks, preferredTag); index >= 0 && ranks[index].policyID == policyID && ranks[index].eligible {
			return index
		}
	}
	for index := range ranks {
		if ranks[index].policyID == policyID && ranks[index].eligible {
			return index
		}
	}
	// The policy backend should only select eligible candidates. Keep a
	// defensive fallback for an inconsistent snapshot so the host can still
	// report the selected policy instead of silently changing endpoints.
	for index := range ranks {
		if ranks[index].policyID == policyID {
			return index
		}
	}
	return -1
}

func smartSameEndpoint(metadataByTag map[string]smartCandidateMetadata, left, right string) bool {
	if left == right {
		return true
	}
	leftMetadata, leftFound := metadataByTag[left]
	rightMetadata, rightFound := metadataByTag[right]
	if leftFound && rightFound {
		if smartMetadataSameEndpoint(leftMetadata, rightMetadata) {
			return true
		}
	}
	return smartEquivalentLine(left, right)
}

func smartRemapCandidateAlias(tag string, oldMetadataByTag, newMetadataByTag map[string]smartCandidateMetadata, candidates []adapter.Outbound) string {
	if tag == "" {
		return ""
	}
	if _, found := newMetadataByTag[tag]; found {
		return tag
	}
	oldMetadata, found := oldMetadataByTag[tag]
	if !found {
		return tag
	}
	for _, candidate := range candidates {
		newMetadata, found := newMetadataByTag[candidate.Tag()]
		if found && smartMetadataSameEndpoint(oldMetadata, newMetadata) {
			return candidate.Tag()
		}
	}
	return tag
}

func smartMetadataSameEndpoint(left, right smartCandidateMetadata) bool {
	if left.policyID != 0 && left.policyID == right.policyID {
		return true
	}
	if left.profileID != "" && left.profileID == right.profileID {
		return true
	}
	return left.identity != "" && left.identity == right.identity
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
		metadata := s.candidateMetadataByTag[previous]
		s.access.RUnlock()
		forceAll = s.probeRegistry.dead(metadata.probeKey)
	}
	if !forceAll {
		forceAll = s.store.candidateDead(networkKey, siteKey, s.candidateProfileID(previous), transport, time.Now())
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
	now := time.Now()
	phase := s.currentPhase().String()
	contextKey := smartSelectionKey(networkKey, siteDisplay, transport)
	selectedEndpointID := ""
	if selectedRank, found := smartRankByTag(ranks, selected); found {
		selectedEndpointID = selectedRank.status.EndpointID
		if selectedEndpointID == "" {
			selectedEndpointID = smartEndpointID(selectedRank.identity, selectedRank.policyID)
		}
	}
	pinned, _, _, _ := s.controlSnapshot(now)
	statusCount := min(len(ranks), smartStatusCandidateLimit)
	s.statusAccess.Lock()
	// Identical decisions within a short window are coalesced. Selection and
	// failure reasons are still published immediately; only repeated healthy
	// ranking snapshots from connection fan-out take the fast path.
	if !s.statusLastAt.IsZero() && now.Sub(s.statusLastAt) < smartStatusMinPublishInterval &&
		s.statusLastContext == contextKey && s.statusLastSelected == selected &&
		s.statusLastReason == reason && s.statusLastPhase == phase {
		s.statusAccess.Unlock()
		return
	}
	statuses := s.status.Candidates[:0]
	if cap(statuses) < statusCount {
		statuses = make([]adapter.SmartCandidateStatus, 0, statusCount)
	}
	primaryAssigned := false
	appendStatus := func(rank smartRank) {
		if len(statuses) >= statusCount {
			return
		}
		status := rank.status
		switch {
		case selected != "" && rank.outbound.Tag() == selected:
			status.Role = "primary"
			primaryAssigned = true
		case !rank.eligible || rank.status.State == "open":
			status.Role = "standby"
		case !primaryAssigned:
			status.Role = "primary"
			primaryAssigned = true
		default:
			status.Role = "backup"
		}
		statuses = append(statuses, status)
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
		appendStatus(ranks[selectedIndex])
	}
	for index := range ranks {
		if len(statuses) >= statusCount {
			break
		}
		if ranks[index].outbound.Tag() == selected {
			continue
		}
		appendStatus(ranks[index])
	}
	profile := smartProfileInteractive
	if len(ranks) > 0 {
		profile = ranks[0].profile
	}
	s.status = adapter.SmartGroupStatus{
		Selected:                  selected,
		SelectedEndpointID:        selectedEndpointID,
		Pinned:                    pinned,
		Network:                   networkKey,
		Site:                      siteDisplay,
		Phase:                     s.currentPhase().String(),
		Reason:                    transport + "/" + profile.String() + ": " + reason,
		UpdatedAt:                 now,
		CandidateCount:            len(ranks),
		CandidateDetailsCount:     len(statuses),
		CandidateDetailsTruncated: len(statuses) < len(ranks),
		StateCounts:               stateCounts,
		Candidates:                statuses,
	}
	if s.statusContexts == nil {
		s.statusContexts = make(map[string]adapter.SmartContextStatus)
	}
	if _, loaded := s.statusContexts[contextKey]; !loaded {
		s.statusContextOrder = append(s.statusContextOrder, contextKey)
		if len(s.statusContextOrder) > smartStatusContextLimit {
			oldest := s.statusContextOrder[0]
			s.statusContextOrder = s.statusContextOrder[1:]
			delete(s.statusContexts, oldest)
		}
	}
	s.statusContexts[contextKey] = adapter.SmartContextStatus{
		Network:                   networkKey,
		Site:                      siteDisplay,
		Transport:                 transport,
		Phase:                     s.currentPhase().String(),
		Selected:                  selected,
		SelectedEndpointID:        selectedEndpointID,
		Reason:                    transport + "/" + profile.String() + ": " + reason,
		UpdatedAt:                 s.status.UpdatedAt,
		CandidateCount:            len(ranks),
		CandidateDetailsCount:     len(statuses),
		CandidateDetailsTruncated: len(statuses) < len(ranks),
		StateCounts:               cloneSmartStateCounts(stateCounts),
		Candidates:                append([]adapter.SmartCandidateStatus(nil), statuses...),
	}
	s.statusLastAt = now
	s.statusLastContext = contextKey
	s.statusLastSelected = selected
	s.statusLastReason = reason
	s.statusLastPhase = phase
	s.statusAccess.Unlock()
}

func (s *Smart) setWarmingStatus(reason string) {
	s.statusAccess.Lock()
	s.statusLastAt = time.Time{}
	s.statusLastContext = ""
	s.statusLastSelected = ""
	s.statusLastReason = ""
	s.statusLastPhase = ""
	s.status = adapter.SmartGroupStatus{
		Phase:       s.currentPhase().String(),
		Reason:      "warming: " + reason,
		UpdatedAt:   time.Now(),
		StateCounts: map[string]int{},
		Candidates:  []adapter.SmartCandidateStatus{},
	}
	clear(s.statusContexts)
	s.statusContextOrder = nil
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
	s.resetPolicyBackend()
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
	candidateMetadataByTag := make(map[string]smartCandidateMetadata, len(candidates))
	for _, candidate := range candidates {
		tag := candidate.Tag()
		identity := s.probeIdentityLocked(candidate)
		candidateByTag[tag] = candidate
		candidateMetadataByTag[tag] = s.buildCandidateMetadata(tag, identity)
	}
	s.access.Lock()
	oldMetadataByTag := s.candidateMetadataByTag
	for key, selected := range s.lastSelected {
		s.lastSelected[key] = smartRemapCandidateAlias(selected, oldMetadataByTag, candidateMetadataByTag, candidates)
	}
	for key, affinity := range s.affinity {
		affinity.Candidate = smartRemapCandidateAlias(affinity.Candidate, oldMetadataByTag, candidateMetadataByTag, candidates)
		s.affinity[key] = affinity
	}
	s.candidates = candidates
	s.candidateByTag = candidateByTag
	s.candidateMetadataByTag = candidateMetadataByTag
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
	s.access.RLock()
	for index := range statusCount {
		metadata := s.candidateMetadataByTag[candidates[index].Tag()]
		statuses[index] = adapter.SmartCandidateStatus{
			Tag:        candidates[index].Tag(),
			EndpointID: smartEndpointID(metadata.identity, metadata.policyID),
			State:      "warming",
			Reason:     "awaiting observations",
		}
	}
	s.access.RUnlock()
	s.statusAccess.Lock()
	s.statusLastAt = time.Time{}
	s.statusLastContext = ""
	s.statusLastSelected = ""
	s.statusLastReason = ""
	s.statusLastPhase = ""
	s.status = adapter.SmartGroupStatus{
		Phase:                     s.currentPhase().String(),
		Reason:                    "warming: candidates loaded, awaiting observations",
		UpdatedAt:                 time.Now(),
		CandidateCount:            len(candidates),
		CandidateDetailsCount:     len(statuses),
		CandidateDetailsTruncated: len(statuses) < len(candidates),
		StateCounts:               map[string]int{"warming": len(candidates)},
		Candidates:                statuses,
	}
	clear(s.statusContexts)
	s.statusContextOrder = nil
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
	startedAt        time.Time
	readBytes        atomic.Int64
	writeBytes       atomic.Int64
	firstRead        atomic.Bool
	closeOnce        sync.Once
	failureOnce      sync.Once
	onFirstByte      func(time.Duration)
	onClose          func(int64, time.Duration)
	onRetransmit     func(float64)
	onFailure        func()
	stallOnce        sync.Once
	failureNotified  atomic.Bool
	stallTimeout     time.Duration
	stallTimerAccess sync.Mutex
	stallTimer       *time.Timer
	stallGeneration  uint64
	stallPending     bool
	closed           atomic.Bool
}

func newSmartObservedConn(conn net.Conn, startedAt time.Time, onFirstByte func(time.Duration), onClose func(int64, time.Duration), onFailure func()) net.Conn {
	return newSmartObservedConnWithStall(conn, startedAt, onFirstByte, onClose, onFailure, 0)
}

func newSmartObservedConnWithStall(conn net.Conn, startedAt time.Time, onFirstByte func(time.Duration), onClose func(int64, time.Duration), onFailure func(), stallTimeout time.Duration) net.Conn {
	return newSmartObservedConnWithRetransmit(conn, startedAt, onFirstByte, onClose, nil, onFailure, stallTimeout)
}

func newSmartObservedConnWithRetransmit(conn net.Conn, startedAt time.Time, onFirstByte func(time.Duration), onClose func(int64, time.Duration), onRetransmit func(float64), onFailure func(), stallTimeout time.Duration) net.Conn {
	return &smartObservedConn{
		ExtendedConn: bufio.NewExtendedConn(conn),
		startedAt:    startedAt,
		onFirstByte:  onFirstByte,
		onClose:      onClose,
		onRetransmit: onRetransmit,
		onFailure:    onFailure,
		stallTimeout: stallTimeout,
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
		c.closed.Store(true)
		c.stopStallTimer()
		if c.onClose != nil {
			c.onClose(c.readBytes.Load()+c.writeBytes.Load(), time.Since(c.startedAt))
		}
		if c.onRetransmit != nil {
			if ratio, ok := smartTCPRetransmitRatio(c.ExtendedConn); ok {
				c.onRetransmit(ratio)
			}
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
	// A response, including one on an already-established stream, completes
	// the current request phase.  Clearing the timer here keeps idle keep-alive
	// and streaming connections from being treated as failures.
	c.stopStallTimer()
	if c.firstRead.CompareAndSwap(false, true) {
		if c.onFirstByte != nil {
			c.onFirstByte(time.Since(c.startedAt))
		}
	}
}

func (c *smartObservedConn) observeWrite(n int64) {
	if n > 0 {
		c.writeBytes.Add(n)
		c.armStallTimer()
	}
}

func (c *smartObservedConn) armStallTimer() {
	if c.stallTimeout <= 0 || c.closed.Load() || c.failureNotified.Load() {
		return
	}
	c.stallTimerAccess.Lock()
	if c.stallTimer == nil && !c.stallPending && !c.closed.Load() && !c.failureNotified.Load() {
		c.stallGeneration++
		generation := c.stallGeneration
		c.stallPending = true
		c.stallTimer = time.AfterFunc(c.stallTimeout, func() {
			c.observeStall(generation)
		})
	}
	c.stallTimerAccess.Unlock()
}

func (c *smartObservedConn) stopStallTimer() {
	c.stallTimerAccess.Lock()
	c.stallGeneration++
	if c.stallTimer != nil {
		c.stallTimer.Stop()
		c.stallTimer = nil
	}
	c.stallPending = false
	c.stallTimerAccess.Unlock()
}

func (c *smartObservedConn) observeStall(generation uint64) {
	c.stallTimerAccess.Lock()
	if c.closed.Load() || !c.stallPending || generation != c.stallGeneration {
		c.stallTimerAccess.Unlock()
		return
	}
	c.stallTimer = nil
	c.stallPending = false
	c.stallTimerAccess.Unlock()
	c.stallOnce.Do(func() {
		c.notifyFailure()
	})
}

func (c *smartObservedConn) observeFailure(err error) {
	if err != nil {
		// A terminal or classified read/write error ends the current request
		// phase.  Do not leave its timer behind to report a second, synthetic
		// stall after the transport has already told us what happened.
		c.stopStallTimer()
	}
	if !isSmartStreamFailure(err) {
		return
	}
	c.notifyFailure()
}

func (c *smartObservedConn) notifyFailure() {
	c.failureOnce.Do(func() {
		c.failureNotified.Store(true)
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
// A response watchdog is armed by the first successful write for protocols
// that require a reply (DNS, QUIC and STUN). This closes the old gap where a
// half-open UDP/QUIC flow was only reported when its owner happened to close.
type smartObservedPacketConn struct {
	net.PacketConn
	startedAt          time.Time
	expectResponse     bool
	watchdogTimeout    time.Duration
	writePackets       atomic.Uint64
	readPackets        atomic.Uint64
	closeOnce          sync.Once
	noResponseOnce     sync.Once
	onNoResponse       func(time.Duration)
	closed             atomic.Bool
	watchdogAccess     sync.Mutex
	watchdogTimer      *time.Timer
	watchdogGeneration uint64
	watchdogPending    bool
}

func newSmartObservedPacketConn(conn net.PacketConn, startedAt time.Time, expectResponse bool, onNoResponse func(time.Duration)) net.PacketConn {
	return newSmartObservedPacketConnWithWatchdog(conn, startedAt, expectResponse, 0, onNoResponse)
}

func newSmartObservedPacketConnWithWatchdog(conn net.PacketConn, startedAt time.Time, expectResponse bool, watchdogTimeout time.Duration, onNoResponse func(time.Duration)) net.PacketConn {
	base := &smartObservedPacketConn{
		PacketConn:      conn,
		startedAt:       startedAt,
		expectResponse:  expectResponse,
		watchdogTimeout: watchdogTimeout,
		onNoResponse:    onNoResponse,
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
		c.stopWatchdog()
	}
}

func (c *smartObservedPacketConn) observeWrite(count int) {
	if count > 0 {
		c.writePackets.Add(1)
		c.armWatchdog()
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
	} else if c.expectResponse && isSmartPacketFailure(err) {
		c.stopWatchdog()
		c.notifyNoResponse(time.Since(c.startedAt))
	}
	return count, err
}

func (c *smartObservedPacketConn) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.stopWatchdog()
		elapsed := time.Since(c.startedAt)
		if c.expectResponse && c.writePackets.Load() > 0 && c.readPackets.Load() == 0 && elapsed >= time.Second && c.onNoResponse != nil {
			c.notifyNoResponse(elapsed)
		}
	})
	return c.PacketConn.Close()
}

func (c *smartObservedPacketConn) armWatchdog() {
	if !c.expectResponse || c.watchdogTimeout <= 0 || c.closed.Load() {
		return
	}
	c.watchdogAccess.Lock()
	if c.watchdogTimer == nil && !c.watchdogPending && !c.closed.Load() {
		c.watchdogGeneration++
		generation := c.watchdogGeneration
		c.watchdogPending = true
		c.watchdogTimer = time.AfterFunc(c.watchdogTimeout, func() {
			c.observeWatchdog(generation)
		})
	}
	c.watchdogAccess.Unlock()
}

func (c *smartObservedPacketConn) stopWatchdog() {
	c.watchdogAccess.Lock()
	c.watchdogGeneration++
	if c.watchdogTimer != nil {
		c.watchdogTimer.Stop()
		c.watchdogTimer = nil
	}
	c.watchdogPending = false
	c.watchdogAccess.Unlock()
}

func (c *smartObservedPacketConn) observeWatchdog(generation uint64) {
	c.watchdogAccess.Lock()
	if c.closed.Load() || !c.watchdogPending || generation != c.watchdogGeneration {
		c.watchdogAccess.Unlock()
		return
	}
	c.watchdogTimer = nil
	c.watchdogPending = false
	c.watchdogAccess.Unlock()
	c.notifyNoResponse(time.Since(c.startedAt))
}

func (c *smartObservedPacketConn) notifyNoResponse(elapsed time.Duration) {
	c.noResponseOnce.Do(func() {
		if c.onNoResponse != nil {
			c.onNoResponse(elapsed)
		}
	})
}

func isSmartPacketFailure(err error) bool {
	if err == nil || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
		return false
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return true
	}
	return errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ECONNABORTED) ||
		errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ETIMEDOUT)
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
	} else if c.expectResponse && isSmartPacketFailure(err) {
		c.stopWatchdog()
		c.notifyNoResponse(time.Since(c.startedAt))
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
	} else if c.expectResponse && isSmartPacketFailure(err) {
		c.stopWatchdog()
		c.notifyNoResponse(time.Since(c.startedAt))
	}
	return err
}
