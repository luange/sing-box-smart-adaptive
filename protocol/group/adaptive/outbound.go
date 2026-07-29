package adaptive

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/nodefilter"
	"github.com/sagernet/sing-box/common/nodeweight"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/group/probe"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"
)

const (
	defaultProbeURL          = probe.GoogleConnectivityURL
	defaultProbeCoverage     = 10 * time.Minute
	defaultProbeTimeout      = 5 * time.Second
	defaultProbeConcurrency  = 8
	defaultProbeQueueSize    = 4096
	defaultCapabilityRefresh = 5 * time.Minute
	defaultCapabilityTimeout = 20 * time.Second
	defaultStateRetention    = 7 * 24 * time.Hour
	defaultStateMaxEntries   = 4096
	defaultStrictLeaseTTL    = 30 * time.Minute
	defaultAdaptiveLeaseTTL  = 10 * time.Minute
	defaultMaxLeases         = 8192
	defaultMaxAttempts       = 3
	defaultAttemptTimeout    = 4 * time.Second
	defaultHedgeDelay        = 450 * time.Millisecond
	statusCandidateLimit     = 64
)

type adaptivePublishPhase uint8

const (
	publishPhasePrepared adaptivePublishPhase = iota + 1
	publishPhasePublishing
	publishPhaseActive
	publishPhaseRollingBack
	publishPhaseRetired
)

var (
	_ adapter.AdaptivePoolGroup        = (*AdaptivePool)(nil)
	_ adapter.PreMatchDisabledOutbound = (*AdaptivePool)(nil)
	_ adapter.RuntimeEpochLifecycle    = (*AdaptivePool)(nil)
)

type AdaptivePool struct {
	outbound.Adapter
	ctx    context.Context
	logger log.ContextLogger
	source SourceRuntime

	shadow                     bool
	probeURL                   string
	probeCoverage              time.Duration
	probeTimeout               time.Duration
	probeConcurrency           int
	probeQueueSize             int
	probeRunner                func(context.Context, string, N.Dialer) (uint16, error)
	statePath                  string
	groupID                    string
	runtimeManager             *RuntimeManager
	identityKey                [32]byte
	identityKeyNew             bool
	identityHasher             *IdentityHasher
	nodeWeights                *nodeweight.Matcher
	catalog                    *CatalogPort
	health                     *HealthStore
	resolver                   *ServiceResolver
	leases                     *SessionLeaseManager
	policy                     *PolicyEngine
	policyMaxAttempts          int
	manualFailure              string
	runner                     *AttemptRunner
	defaultMode                PolicyMode
	strictLeaseTTL             time.Duration
	adaptiveLeaseTTL           time.Duration
	generation                 atomic.Uint64
	attemptSequence            atomic.Uint64
	missedObservations         atomic.Uint64
	observationStale           atomic.Uint64
	observationDuplicate       atomic.Uint64
	observationBackpressure    atomic.Uint64
	observationReducerFailure  atomic.Uint64
	observationIdentityFailure atomic.Uint64
	observationPanic           atomic.Uint64
	observationPermitBusy      atomic.Uint64
	businessTLSFailures        atomic.Uint64
	transportFailures          atomic.Uint64
	observationReducerHook     func(ObservationEvidence, []DomainEvidence) error
	observationAccess          sync.Mutex
	observationIngestor        *ObservationIngestor
	statePersistenceAccess     sync.Mutex
	statePersistenceFailures   atomic.Uint64
	stateWriter                *adaptiveStateWriter
	control                    *ControlState
	switchAudit                *SwitchAuditStore
	catalogAccess              sync.Mutex
	preparedIdentity           *PreparedIdentity
	preparedExecution          *PreparedExecution
	runtimeIdentity            RuntimeIdentity
	appliedRevision            atomic.Uint64
	sourcePublication          *SourcePublication
	deltaAppliedTotal          atomic.Uint64
	deltaFallbackTotal         atomic.Uint64

	lifecycleAccess         sync.Mutex
	published               bool
	publishPhase            adaptivePublishPhase
	sourceDirty             bool
	postStarted             bool
	retired                 bool
	scheduler               *ProbeScheduler
	schedulerOwner          *SchedulerCoordinator
	schedulerGen            uint64
	capabilityProvider      RefreshableProbeTargetProvider
	capabilityServiceIDs    []string
	capabilityRunner        *CapabilityProbeRunner
	capabilityController    *CapabilityProbeController
	capabilityControllers   map[string]*CapabilityProbeController
	capabilityRefresh       time.Duration
	capabilityTimeout       time.Duration
	capabilityQuorum        int
	capabilityCommonModeMin int
	exitIdentityStore       *ExitIdentityStore
	capabilityInitFailures  atomic.Uint64
	closing                 atomic.Bool
}

func New(ctx context.Context, _ adapter.Router, logger log.ContextLogger, tag string, options option.AdaptivePoolOutboundOptions) (adapter.Outbound, error) {
	if len(options.Outbounds)+len(options.Providers) == 0 && !options.UseAllProviders {
		return nil, errors.New("adaptive_pool requires outbound or provider sources")
	}
	probeURL := options.Probe.URL
	if probeURL == "" {
		probeURL = defaultProbeURL
	}
	probeCoverage := time.Duration(options.Probe.CoverageInterval)
	if probeCoverage <= 0 {
		probeCoverage = defaultProbeCoverage
	}
	probeTimeout := time.Duration(options.Probe.Timeout)
	if probeTimeout <= 0 {
		probeTimeout = defaultProbeTimeout
	}
	probeConcurrency := options.Probe.Concurrency
	if probeConcurrency <= 0 {
		probeConcurrency = defaultProbeConcurrency
	}
	probeQueueSize := options.Probe.QueueSize
	if probeQueueSize <= 0 {
		probeQueueSize = defaultProbeQueueSize
	}
	var capabilityProvider RefreshableProbeTargetProvider
	var capabilityServiceIDs []string
	capabilityRefresh := time.Duration(options.Capability.RefreshInterval)
	capabilityTimeout := time.Duration(options.Capability.Timeout)
	capabilityQuorum := options.Capability.Quorum
	capabilityCommonModeMin := options.Capability.CommonModeMinNodes
	if options.Capability.Enabled {
		if capabilityRefresh < 0 || capabilityTimeout < 0 || capabilityQuorum < 0 || capabilityCommonModeMin < 0 {
			return nil, errors.New("adaptive capability policy is invalid")
		}
		if capabilityRefresh == 0 {
			capabilityRefresh = defaultCapabilityRefresh
		}
		if capabilityTimeout == 0 {
			capabilityTimeout = defaultCapabilityTimeout
		}
		if capabilityQuorum == 0 {
			if options.Capability.BuiltinYouTubeTLS || options.Capability.BuiltinAIServiceTLS || options.Capability.BuiltinExitIdentity {
				capabilityQuorum = 1
			} else {
				capabilityQuorum = 2
			}
		}
		if capabilityCommonModeMin == 0 {
			capabilityCommonModeMin = 2
		}
		if capabilityCommonModeMin < 2 {
			return nil, errors.New("adaptive capability common-mode threshold is invalid")
		}
		if options.Capability.BuiltinYouTubeTLS && options.Capability.BuiltinAIServiceTLS {
			return nil, errors.New("adaptive builtin capability modes are ambiguous")
		}
		if options.Capability.BuiltinYouTubeTLS || options.Capability.BuiltinAIServiceTLS || options.Capability.BuiltinExitIdentity {
			if capabilityQuorum != 1 {
				return nil, errors.New("adaptive builtin capability requires quorum 1")
			}
			if options.Capability.ManifestURL != "" || len(options.Capability.TrustedKeys) != 0 {
				return nil, errors.New("adaptive builtin capability cannot use manifest trust options")
			}
			builtinProvider, providerErr := NewBuiltinCapabilityTargetProvider(nil, options.Capability.BuiltinYouTubeTLS, options.Capability.BuiltinAIServiceTLS, options.Capability.BuiltinExitIdentity)
			if providerErr != nil {
				return nil, errors.New("adaptive builtin capability is invalid")
			}
			capabilityProvider = builtinProvider
			capabilityServiceIDs = builtinProvider.ServiceIDs()
		} else {
			trustedKeys, keyErr := parseCapabilityTrustedKeys(options.Capability.TrustedKeys)
			if keyErr != nil {
				return nil, keyErr
			}
			fetcher, fetcherErr := NewHTTPSignedProbeTargetFetcher(options.Capability.ManifestURL, nil)
			if fetcherErr != nil {
				return nil, errors.New("adaptive capability manifest endpoint is invalid")
			}
			trustedProvider, providerErr := NewTrustedYouTubeTargetProvider(nil, fetcher, trustedKeys)
			if providerErr != nil {
				return nil, errors.New("adaptive capability trust configuration is invalid")
			}
			capabilityProvider = trustedProvider
			capabilityServiceIDs = []string{youtubeProbeServiceID}
		}
	}
	var exitIdentityStore *ExitIdentityStore
	if options.Capability.Enabled && options.Capability.BuiltinExitIdentity {
		identityStore, identityErr := NewExitIdentityStore(tag)
		if identityErr != nil {
			return nil, identityErr
		}
		exitIdentityStore = identityStore
	}
	stateRetention := time.Duration(options.State.Retention)
	if stateRetention <= 0 {
		stateRetention = defaultStateRetention
	}
	stateMaxEntries := options.State.MaxEntries
	if stateMaxEntries <= 0 {
		stateMaxEntries = defaultStateMaxEntries
	}
	defaultMode := PolicyMode(options.Policy.Default)
	if defaultMode == "" {
		defaultMode = ModeAdaptive
	}
	if defaultMode != ModeAdaptive && defaultMode != ModeStrictAffinity && defaultMode != ModeLatency && defaultMode != ModeBulk {
		return nil, E.New("unknown adaptive default policy: ", defaultMode)
	}
	strictLeaseTTL := time.Duration(options.Policy.StrictLeaseTTL)
	if strictLeaseTTL <= 0 {
		strictLeaseTTL = defaultStrictLeaseTTL
	}
	adaptiveLeaseTTL := time.Duration(options.Policy.AdaptiveLeaseTTL)
	if adaptiveLeaseTTL <= 0 {
		adaptiveLeaseTTL = defaultAdaptiveLeaseTTL
	}
	maxLeases := options.Policy.MaxLeases
	if maxLeases <= 0 {
		maxLeases = defaultMaxLeases
	}
	maxAttempts := options.Policy.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = defaultMaxAttempts
	}
	attemptTimeout := time.Duration(options.Policy.AttemptTimeout)
	if attemptTimeout <= 0 {
		attemptTimeout = defaultAttemptTimeout
	}
	hedgeDelay := time.Duration(options.Policy.HedgeDelay)
	if hedgeDelay <= 0 {
		hedgeDelay = defaultHedgeDelay
	}
	manualFailure := options.Policy.ManualFailure
	if manualFailure == "" {
		manualFailure = "fallback"
	}
	if manualFailure != "fallback" && manualFailure != "fail_closed" {
		return nil, E.New("unknown adaptive manual_failure: ", manualFailure)
	}
	statePath := options.State.Path
	if statePath == "" {
		statePath = "adaptive-state-" + safeFileName(tag)
	}
	statePath = filemanager.BasePath(ctx, statePath)
	identityKey, keyNew, err := loadOrPrepareIdentityKey(statePath + ".key")
	if err != nil {
		return nil, err
	}
	hasher, err := NewIdentityHasher(identityKey[:])
	if err != nil {
		return nil, err
	}
	health := NewHealthStore(stateRetention, stateMaxEntries)
	resolver := NewServiceResolver(hasher, defaultMode)
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
	sourceRuntime, err := NewA48SourceRuntimeV1(ctx, hasher, SourceRuntimeConfig{
		StaticTags:    options.Outbounds,
		ProviderTags:  options.Providers,
		UseAll:        options.UseAllProviders,
		Include:       (*regexp.Regexp)(options.Include),
		Exclude:       (*regexp.Regexp)(options.Exclude),
		ManualExclude: manualExclude,
	})
	if err != nil {
		return nil, err
	}
	runtimeManager := service.PtrFromContext[RuntimeManager](ctx)
	if runtimeManager == nil {
		runtimeManager = NewRuntimeManager()
	}
	// Register before looking up the coordinator so an old drain waiter cannot
	// delete it between lookup and publication of this pool's user reference.
	runtimeManager.RegisterGroup(tag)
	catalog := NewCatalogPort()
	pool := &AdaptivePool{
		Adapter:                 outbound.NewAdapter(C.TypeAdaptivePool, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.Outbounds),
		ctx:                     ctx,
		logger:                  logger,
		source:                  sourceRuntime,
		shadow:                  options.Shadow,
		probeURL:                probeURL,
		probeCoverage:           probeCoverage,
		probeTimeout:            probeTimeout,
		probeConcurrency:        probeConcurrency,
		probeQueueSize:          probeQueueSize,
		capabilityProvider:      capabilityProvider,
		capabilityServiceIDs:    capabilityServiceIDs,
		capabilityRefresh:       capabilityRefresh,
		capabilityTimeout:       capabilityTimeout,
		capabilityQuorum:        capabilityQuorum,
		capabilityCommonModeMin: capabilityCommonModeMin,
		exitIdentityStore:       exitIdentityStore,
		probeRunner:             urltest.URLTest,
		statePath:               statePath,
		groupID:                 tag,
		runtimeManager:          runtimeManager,
		schedulerOwner:          runtimeManager.SchedulerCoordinator(tag),
		identityKey:             identityKey,
		identityKeyNew:          keyNew,
		identityHasher:          hasher,
		nodeWeights:             nodeWeights,
		catalog:                 catalog,
		health:                  health,
		resolver:                resolver,
		leases:                  NewSessionLeaseManager(maxLeases),
		policy:                  NewPolicyEngine(health, maxAttempts, manualFailure).BindNodeWeights(nodeWeights),
		policyMaxAttempts:       maxAttempts,
		manualFailure:           manualFailure,
		runner:                  NewAttemptRunner(attemptTimeout, hedgeDelay, catalog),
		defaultMode:             defaultMode,
		strictLeaseTTL:          strictLeaseTTL,
		adaptiveLeaseTTL:        adaptiveLeaseTTL,
		control:                 new(ControlState),
		switchAudit:             NewSwitchAuditStore(),
		observationIngestor:     NewObservationIngestor(nil, nil, 10*time.Minute, 16384),
	}
	pool.policy.BindBulkSequence(&pool.control.bulkSequence)
	pool.loadPersistentState()
	return pool, nil
}

func (p *AdaptivePool) Start() error {
	// Configuration checks construct outbounds but do not start them. Starting
	// the writer in New leaked one goroutine and retained the entire validation
	// Box on every reload because an unstarted outbound manager has nothing to
	// close. Background ownership begins only with the real runtime lifecycle.
	if p.stateWriter == nil {
		p.stateWriter = newAdaptiveStateWriter(p)
	}
	if err := p.source.Start(p.onSourceUpdated); err != nil {
		p.stateWriter.Close()
		p.stateWriter = nil
		return err
	}
	if err := p.rebuild(); err != nil {
		_ = p.source.Close()
		p.stateWriter.Close()
		p.stateWriter = nil
		return err
	}
	return nil
}

func (p *AdaptivePool) PostStart() error {
	p.lifecycleAccess.Lock()
	p.postStarted = true
	p.startSchedulerLocked()
	p.lifecycleAccess.Unlock()
	return nil
}

func (p *AdaptivePool) OnRuntimeEpochPublish() error {
	p.lifecycleAccess.Lock()
	if p.publishPhase != publishPhasePrepared {
		p.lifecycleAccess.Unlock()
		return errors.New("adaptive runtime epoch is not in prepared phase")
	}
	if p.identityKeyNew {
		p.lifecycleAccess.Unlock()
		return errors.New("adaptive identity key is not durable")
	}
	p.publishPhase = publishPhasePublishing
	p.lifecycleAccess.Unlock()

	p.catalogAccess.Lock()
	preparedIdentity := p.preparedIdentity
	preparedExecution := p.preparedExecution
	if preparedIdentity == nil || preparedExecution == nil {
		p.catalogAccess.Unlock()
		return errors.New("adaptive runtime epoch was not prepared")
	}
	shared, identity, err := preparedIdentity.Commit()
	if err != nil {
		p.catalogAccess.Unlock()
		return err
	}
	p.runtimeIdentity = identity
	p.lifecycleAccess.Lock()
	if p.publishPhase == publishPhasePublishing {
		p.health = shared.health
		p.leases = shared.leases
		p.control = shared.control
		p.policy = NewPolicyEngine(p.health, p.policyMaxAttempts, p.manualFailure).BindNodeWeights(p.nodeWeights).BindBulkSequence(&p.control.bulkSequence)
	}
	p.lifecycleAccess.Unlock()
	if err = p.persistStateDurable(); err != nil {
		_ = preparedIdentity.Rollback()
		p.runtimeIdentity = RuntimeIdentity{}
		p.catalogAccess.Unlock()
		return errors.New("adaptive identity state is not durable")
	}
	p.catalog.CommitPrepared(preparedExecution)
	p.catalogAccess.Unlock()
	return nil
}

func (p *AdaptivePool) OnRuntimeEpochPublishCommit() {
	p.catalogAccess.Lock()
	identity := cloneRuntimeIdentity(p.runtimeIdentity)
	p.catalogAccess.Unlock()
	p.applyCommittedTransitions(identity)
	p.lifecycleAccess.Lock()
	if p.publishPhase != publishPhasePublishing {
		p.lifecycleAccess.Unlock()
		return
	}
	p.publishPhase = publishPhaseActive
	p.published = true
	dirty := p.sourceDirty
	p.sourceDirty = false
	p.startSchedulerLocked()
	p.lifecycleAccess.Unlock()
	if dirty {
		if err := p.rebuild(); err != nil && p.logger != nil {
			p.logger.Error("replay adaptive source update after epoch publish: ", err)
		}
	}
}

func (p *AdaptivePool) OnRuntimeEpochPublishRollback() {
	p.lifecycleAccess.Lock()
	p.publishPhase = publishPhaseRollingBack
	p.published = false
	p.sourceDirty = false
	p.lifecycleAccess.Unlock()
	p.catalogAccess.Lock()
	prepared := p.preparedIdentity
	epochID := p.runtimeIdentity.EpochID
	p.runtimeIdentity = RuntimeIdentity{}
	p.catalogAccess.Unlock()
	if prepared != nil {
		_ = prepared.Rollback()
	}
	p.catalog.RollbackEpoch(epochID)
	_ = p.persistStateDurable()
	p.OnRuntimeEpochRetire()
}

func (p *AdaptivePool) OnRuntimeEpochRetire() {
	p.lifecycleAccess.Lock()
	p.retired = true
	p.publishPhase = publishPhaseRetired
	capabilityControllers := p.capabilityControllers
	legacyCapabilityController := p.capabilityController
	p.capabilityController = nil
	p.capabilityControllers = nil
	scheduler := p.scheduler
	p.scheduler = nil
	coordinator := p.schedulerOwner
	ownerGeneration := p.schedulerGen
	p.schedulerGen = 0
	p.lifecycleAccess.Unlock()
	for _, capabilityController := range capabilityControllers {
		capabilityController.Close()
	}
	if legacyCapabilityController != nil {
		if current, loaded := capabilityControllers[youtubeProbeServiceID]; !loaded || current != legacyCapabilityController {
			legacyCapabilityController.Close()
		}
	}
	p.catalogAccess.Lock()
	epochID := p.runtimeIdentity.EpochID
	p.catalogAccess.Unlock()
	if epochID != 0 {
		p.runtimeManager.RetireEpoch(p.groupID, epochID)
	}
	if coordinator != nil && epochID != 0 && ownerGeneration != 0 {
		coordinator.Release(epochID, ownerGeneration)
	}
	if scheduler != nil {
		_ = scheduler.Close()
	}
}

func (p *AdaptivePool) Close() error {
	if !p.closing.CompareAndSwap(false, true) {
		return nil
	}
	p.OnRuntimeEpochRetire()
	if p.source != nil {
		_ = p.source.Close()
	}
	if p.stateWriter != nil {
		p.stateWriter.Close()
	}
	p.runtimeManager.UnregisterGroup(p.groupID)
	return nil
}

func (p *AdaptivePool) Network() []string { return []string{N.NetworkTCP, N.NetworkUDP} }

func (p *AdaptivePool) Now() string {
	if p.control == nil {
		return ""
	}
	p.control.access.RLock()
	defer p.control.access.RUnlock()
	if p.shadow {
		return "shadow"
	}
	return p.control.latestTag
}

func (p *AdaptivePool) All() []string {
	snapshot := p.catalog.load()
	if snapshot == nil {
		return nil
	}
	tags := make([]string, len(snapshot.Candidates))
	for index, candidate := range snapshot.Candidates {
		tags[index] = candidate.PrimaryTag
	}
	return tags
}

func (p *AdaptivePool) SelectAdaptiveOutbound(tag string) bool {
	return p.selectAdaptiveOutbound(tag, nil)
}

func (p *AdaptivePool) SelectAdaptiveOutboundAt(tag string, expected uint64) bool {
	return p.selectAdaptiveOutbound(tag, &expected)
}

func (p *AdaptivePool) selectAdaptiveOutbound(tag string, expected *uint64) bool {
	snapshot := p.catalog.load()
	if snapshot == nil {
		return false
	}
	nodeID, loaded := snapshot.AliasToID[tag]
	if !loaded {
		return false
	}
	if p.control == nil {
		p.control = new(ControlState)
	}
	p.control.access.Lock()
	if expected != nil && p.control.revision.Load() != *expected {
		p.control.access.Unlock()
		return false
	}
	p.control.pinned = nodeID
	p.control.pinnedTag = tag
	p.control.revision.Add(1)
	p.control.access.Unlock()
	p.leases.Clear()
	p.persistState()
	return true
}

func (p *AdaptivePool) ClearAdaptiveSelection() {
	_ = p.clearAdaptiveSelection(nil)
}

func (p *AdaptivePool) ClearAdaptiveSelectionAt(expected uint64) bool {
	return p.clearAdaptiveSelection(&expected)
}

func (p *AdaptivePool) clearAdaptiveSelection(expected *uint64) bool {
	if p.control == nil {
		p.control = new(ControlState)
	}
	p.control.access.Lock()
	if expected != nil && p.control.revision.Load() != *expected {
		p.control.access.Unlock()
		return false
	}
	p.control.pinned = NodeID{}
	p.control.pinnedTag = ""
	p.control.revision.Add(1)
	p.control.access.Unlock()
	p.leases.Clear()
	p.persistState()
	return true
}

func (p *AdaptivePool) AdaptiveSelectionRevision() uint64 {
	if p.control == nil {
		return 0
	}
	return p.control.revision.Load()
}

func (p *AdaptivePool) SetAdaptiveServiceOverride(serviceID, mode string, ttl time.Duration, expectedRevision uint64) error {
	if p.control == nil {
		return errors.New("adaptive control revision conflict")
	}
	p.control.access.Lock()
	if p.control.revision.Load() != expectedRevision {
		p.control.access.Unlock()
		return errors.New("adaptive control revision conflict")
	}
	if err := p.resolver.SetOverride(serviceID, PolicyMode(mode), ttl, time.Now()); err != nil {
		p.control.access.Unlock()
		return err
	}
	p.control.revision.Add(1)
	p.control.access.Unlock()
	p.persistState()
	return nil
}

func (p *AdaptivePool) ClearAdaptiveServiceOverride(serviceID string, expectedRevision uint64) error {
	if p.control == nil {
		return errors.New("adaptive control revision conflict")
	}
	p.control.access.Lock()
	if p.control.revision.Load() != expectedRevision {
		p.control.access.Unlock()
		return errors.New("adaptive control revision conflict")
	}
	if !p.resolver.ClearOverride(serviceID) {
		p.control.access.Unlock()
		return errors.New("adaptive service override not found")
	}
	p.control.revision.Add(1)
	p.control.access.Unlock()
	p.persistState()
	return nil
}

func (p *AdaptivePool) AdaptiveServiceOverrides() []adapter.AdaptiveServiceOverride {
	overrides := p.resolver.Overrides(time.Now())
	result := make([]adapter.AdaptiveServiceOverride, len(overrides))
	for index, override := range overrides {
		result[index] = adapter.AdaptiveServiceOverride{ServiceID: override.ServiceID, Mode: string(override.Mode), ExpiresAt: override.ExpiresAt}
	}
	return result
}

func (*AdaptivePool) DisablePreMatch() {}

func (p *AdaptivePool) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if p.shadow {
		return nil, errors.New("adaptive_pool is running in shadow mode and cannot carry traffic")
	}
	if err := p.waitUntilPublished(ctx); err != nil {
		return nil, err
	}
	serviceContext := p.resolver.Resolve(adapter.ContextFrom(ctx), destination, N.NetworkName(network))
	snapshot := p.catalog.load()
	var lease SessionLease
	var reservation *LeaseReservation
	var err error
	if modeUsesLease(serviceContext.Mode) {
		lease, reservation, err = p.leases.Reserve(ctx, serviceContext.Session, time.Now())
		if err != nil {
			return nil, err
		}
	}
	var leasePointer *SessionLease
	if modeUsesLease(serviceContext.Mode) && reservation == nil {
		leasePointer = &lease
	}
	pinned := p.pinnedNodeID()
	plan, err := p.policy.Plan(snapshot, serviceContext, leasePointer, pinned)
	if err != nil {
		if reservation != nil {
			reservation.Abort()
		}
		return nil, err
	}
	startedAt := time.Now()
	conn, candidate, err := p.runner.Dial(ctx, network, destination, plan, p.beginDialAttempt(snapshot, serviceContext))
	if err != nil {
		if reservation != nil {
			reservation.Abort()
		}
		return nil, err
	}
	if modeUsesLease(serviceContext.Mode) {
		previous := NodeHandle{NodeID: lease.NodeID, Slot: lease.NodeSlot, Version: lease.NodeVersion}
		ttl := p.leaseTTL(serviceContext.Mode)
		if reservation != nil {
			reservation.CommitHandle(candidate.Handle, serviceContext.ID, serviceContext.Mode, ttl, time.Now())
		} else if lease.NodeID != candidate.ID || lease.NodeSlot != candidate.Handle.Slot || lease.NodeVersion != candidate.Handle.Version {
			p.leases.ReplaceHandle(serviceContext.Session, NodeHandle{NodeID: lease.NodeID, Slot: lease.NodeSlot, Version: lease.NodeVersion}, candidate.Handle, serviceContext.ID, serviceContext.Mode, ttl, time.Now())
		} else {
			p.leases.RenewHandle(serviceContext.Session, candidate.Handle, ttl, time.Now())
		}
		p.switchAudit.RecordSelection(serviceContext.Session, serviceContext.ID, previous, candidate, plan.Reason, time.Now())
	}
	p.setLatest(candidate.PrimaryTag)
	return p.wrapBusinessConn(conn, snapshot, candidate, serviceContext, startedAt), nil
}

func (p *AdaptivePool) waitUntilPublished(ctx context.Context) error {
	p.lifecycleAccess.Lock()
	phase := p.publishPhase
	published := p.published
	retired := p.retired
	p.lifecycleAccess.Unlock()
	// Zero is used by isolated/unit pools which do not participate in the
	// runtime epoch publication protocol.
	if phase == 0 || published {
		return nil
	}
	if retired || phase == publishPhaseRollingBack || phase == publishPhaseRetired {
		return errors.New("adaptive pool runtime epoch is unavailable")
	}
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("adaptive pool runtime epoch publication timed out")
		case <-ticker.C:
			p.lifecycleAccess.Lock()
			published = p.published
			phase = p.publishPhase
			retired = p.retired
			p.lifecycleAccess.Unlock()
			if published {
				return nil
			}
			if retired || phase == publishPhaseRollingBack || phase == publishPhaseRetired {
				return errors.New("adaptive pool runtime epoch is unavailable")
			}
		}
	}
}

func (p *AdaptivePool) beginDialAttempt(snapshot *ExecutionSnapshot, service ServiceContext) AttemptBegin {
	if snapshot == nil || snapshot.RuntimeEpochID == 0 || snapshot.CatalogRevision == 0 || p.runtimeManager == nil {
		return nil
	}
	return func(candidate Candidate, permit *AttemptPermit) (AttemptComplete, error) {
		attempt, err := p.beginObservationAttempt(snapshot, candidate, permit, service.Transport)
		if err != nil {
			return nil, err
		}
		return func(result DialAttemptResult) {
			p.completeTransportAttempt(attempt, service, result.Err, result.Delay, result.Deferred, result.Panic)
		}, nil
	}
}

func (p *AdaptivePool) completeTransportAttempt(attempt *observationAttempt, service ServiceContext, attemptErr error, delay time.Duration, deferred, implementationFailure bool) {
	defer attempt.lease.Release()
	evidence := attempt.evidence
	evidence.Source = SourceDial
	evidence.Confidence = ConfidenceHigh
	evidence.Delay = delay
	evidence.At = time.Now()
	evidence.Reason = errorReason(attemptErr)
	switch {
	case deferred || errors.Is(attemptErr, context.Canceled):
		evidence.Stage, evidence.Outcome, evidence.Failure = StageDestinationTransport, OutcomeDeferred, FailureCanceled
	case implementationFailure:
		evidence.Stage, evidence.Outcome, evidence.Failure = StageProxyTunnel, OutcomeFailure, FailureProtocol
	case attemptErr == nil:
		evidence.Stage, evidence.Outcome, evidence.Failure = StageDestinationTransport, OutcomeSuccess, FailureNone
	case errors.Is(attemptErr, context.DeadlineExceeded):
		evidence.Stage, evidence.Outcome, evidence.Failure = StageDestinationTransport, OutcomeFailure, FailureTimeout
	default:
		evidence.Stage, evidence.Outcome, evidence.Failure = StageDestinationTransport, OutcomeFailure, FailureConnect
	}
	disposition, publishErr := PublishSettledObservationGuarded(p.sharedObservationIngestor(), attempt.guard, evidence, attempt.reducer)
	p.recordObservationResult(disposition, publishErr)
	if publishErr == nil && disposition == IngestAccepted && evidence.Outcome == OutcomeFailure && evidence.Stage == StageDestinationTransport {
		p.transportFailures.Add(1)
		if snapshot := p.catalog.load(); snapshot != nil {
			if candidate, loaded := snapshot.Candidate(evidence.Handle.NodeID); loaded {
				p.switchAudit.RecordFailure(service.Session, service.ID, candidate, evidence.Failure, "destination_transport", evidence.At)
			}
		}
		status := p.health.StatusHandle(evidence.Handle, DomainTransport, service.Transport, "")
		if modeUsesLease(service.Mode) && (status.Breaker == BreakerOpen || status.Breaker == BreakerCooldown) {
			p.leases.Invalidate(service.Session, evidence.Handle.NodeID)
			p.persistState()
		}
		p.scheduleFailureProbe(evidence.Handle)
	}
}

// scheduleFailureProbe feeds real connection failures back into the existing
// scheduler. Submit coalesces an on-demand probe with an active or pending
// periodic probe, so an outage cannot create a second scheduler or an
// unbounded probe fan-out.
func (p *AdaptivePool) scheduleFailureProbe(handle NodeHandle) {
	p.lifecycleAccess.Lock()
	scheduler := p.scheduler
	p.lifecycleAccess.Unlock()
	if scheduler == nil {
		return
	}
	snapshot := p.catalog.load()
	if snapshot == nil {
		return
	}
	candidate, loaded := snapshot.Candidate(handle.NodeID)
	if !loaded || candidate.Handle.Slot != handle.Slot || candidate.Handle.Version != handle.Version {
		return
	}
	_ = scheduler.Submit(p.probeTask(snapshot, candidate, time.Now(), 0))
}

type observationAttempt struct {
	lease    *RuntimeEpochIdentityLease
	evidence ObservationEvidence
	guard    ObservationIdentityGuard
	reducer  *HealthObservationReducer
}

func (p *AdaptivePool) beginObservationAttempt(snapshot *ExecutionSnapshot, candidate Candidate, permit *AttemptPermit, transport string) (*observationAttempt, error) {
	lease, err := p.runtimeManager.AcquireEpoch(p.groupID, snapshot.RuntimeEpochID)
	if err != nil {
		return nil, err
	}
	evidence := ObservationEvidence{RuntimeEpochID: snapshot.RuntimeEpochID, CatalogRevision: snapshot.CatalogRevision, SourceGeneration: snapshot.Generation, Handle: candidate.Handle, AttemptID: AttemptID(p.attemptSequence.Add(1)), Transport: transport}
	guard := RuntimeEpochObservationGuard{Lease: lease}
	reducer := &HealthObservationReducer{Store: p.health, Settlement: AttemptPermitSettlement{Permit: permit}, BeforeReduce: p.observationReducerHook}
	return &observationAttempt{lease: lease, evidence: evidence, guard: guard, reducer: reducer}, nil
}

func (p *AdaptivePool) sharedObservationIngestor() *ObservationIngestor {
	p.observationAccess.Lock()
	if p.observationIngestor == nil {
		p.observationIngestor = NewObservationIngestor(nil, nil, 10*time.Minute, 16384)
	}
	ingestor := p.observationIngestor
	p.observationAccess.Unlock()
	return ingestor
}

func (p *AdaptivePool) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if p.shadow {
		return nil, errors.New("adaptive_pool is running in shadow mode and cannot carry traffic")
	}
	if err := p.waitUntilPublished(ctx); err != nil {
		return nil, err
	}
	serviceContext := p.resolver.Resolve(adapter.ContextFrom(ctx), destination, N.NetworkUDP)
	snapshot := p.catalog.load()
	var lease SessionLease
	var reservation *LeaseReservation
	var err error
	if modeUsesLease(serviceContext.Mode) {
		lease, reservation, err = p.leases.Reserve(ctx, serviceContext.Session, time.Now())
		if err != nil {
			return nil, err
		}
	}
	var leasePointer *SessionLease
	if modeUsesLease(serviceContext.Mode) && reservation == nil {
		leasePointer = &lease
	}
	plan, err := p.policy.Plan(snapshot, serviceContext, leasePointer, p.pinnedNodeID())
	if err != nil {
		if reservation != nil {
			reservation.Abort()
		}
		return nil, err
	}
	var attemptErrors []error
	for _, candidate := range plan.Candidates {
		permit, allowed := plan.TryAcquireAttemptPermit(candidate.ID, time.Time{})
		if !allowed {
			attemptErrors = append(attemptErrors, E.Cause(ErrBreakerAttemptDeferred, "adaptive UDP candidate ", candidate.PrimaryTag))
			continue
		}
		var observation *observationAttempt
		if snapshot != nil && snapshot.RuntimeEpochID != 0 && snapshot.CatalogRevision != 0 && p.runtimeManager != nil {
			observation, err = p.beginObservationAttempt(snapshot, candidate, permit, N.NetworkUDP)
			if err != nil {
				permit.ReleaseDeferred()
				attemptErrors = append(attemptErrors, E.Cause(err, "prepare adaptive UDP observation ", candidate.PrimaryTag))
				continue
			}
		}
		startedAt := time.Now()
		settle := func(attemptErr error, deferred bool) {
			if observation == nil {
				permit.ReleaseDeferred()
				return
			}
			p.completeTransportAttempt(observation, serviceContext, attemptErr, time.Since(startedAt), deferred, false)
		}
		attemptCtx, cancel := context.WithTimeout(ctx, p.runner.attemptTimeout)
		var packetConn net.PacketConn
		var attemptErr error
		execution, loaded := p.catalog.AcquireExecution(ExecutionToken{RuntimeEpochID: plan.RuntimeEpochID, CatalogRevision: plan.CatalogRevision, Handle: candidate.Handle})
		if !loaded {
			attemptErr = ErrExecutionBindingUnavailable
		} else {
			packetConn, attemptErr = execution.Port.ListenPacket(attemptCtx, destination)
			execution.Release()
		}
		parentCanceled := ctx.Err() != nil
		cancel()
		if attemptErr == nil && packetConn == nil {
			attemptErr = errors.New("adaptive outbound returned nil packet connection")
		}
		if attemptErr == nil && parentCanceled {
			_ = packetConn.Close()
			attemptErr = ctx.Err()
		}
		if parentCanceled {
			settle(attemptErr, true)
			attemptErrors = append(attemptErrors, attemptErr)
			continue
		}
		if attemptErr != nil {
			settle(attemptErr, false)
			attemptErrors = append(attemptErrors, E.Cause(attemptErr, "adaptive UDP candidate ", candidate.PrimaryTag))
			continue
		}
		// PacketConn creation proves destination transport setup only. Actual UDP
		// response evidence and its epoch lease belong to B2b.
		settle(nil, false)
		if modeUsesLease(serviceContext.Mode) {
			previous := NodeHandle{NodeID: lease.NodeID, Slot: lease.NodeSlot, Version: lease.NodeVersion}
			ttl := p.leaseTTL(serviceContext.Mode)
			if reservation != nil {
				reservation.CommitHandle(candidate.Handle, serviceContext.ID, serviceContext.Mode, ttl, time.Now())
			} else if lease.NodeID != candidate.ID || lease.NodeSlot != candidate.Handle.Slot || lease.NodeVersion != candidate.Handle.Version {
				p.leases.ReplaceHandle(serviceContext.Session, NodeHandle{NodeID: lease.NodeID, Slot: lease.NodeSlot, Version: lease.NodeVersion}, candidate.Handle, serviceContext.ID, serviceContext.Mode, ttl, time.Now())
			} else {
				p.leases.RenewHandle(serviceContext.Session, candidate.Handle, ttl, time.Now())
			}
			p.switchAudit.RecordSelection(serviceContext.Session, serviceContext.ID, previous, candidate, plan.Reason, time.Now())
		}
		p.setLatest(candidate.PrimaryTag)
		return p.wrapBusinessPacketConn(packetConn, snapshot, candidate, serviceContext, startedAt), nil
	}
	if reservation != nil {
		reservation.Abort()
	}
	if len(attemptErrors) == 0 {
		return nil, ErrNoEligibleCandidates
	}
	return nil, errors.Join(attemptErrors...)
}

func (p *AdaptivePool) URLTest(ctx context.Context) (map[string]uint16, error) {
	p.lifecycleAccess.Lock()
	scheduler := p.scheduler
	p.lifecycleAccess.Unlock()
	if scheduler == nil {
		return nil, errors.New("adaptive probe scheduler is not running")
	}
	snapshot := p.catalog.load()
	if snapshot == nil {
		return nil, ErrNoCandidates
	}
	result := make(map[string]uint16)
	type pendingProbe struct {
		tag    string
		future *ProbeFuture
	}
	pending := make([]pendingProbe, 0, len(snapshot.Candidates))
	for _, candidate := range snapshot.Candidates {
		submission := scheduler.Submit(p.probeTask(snapshot, candidate, time.Now(), 0))
		if submission.Err != nil {
			for _, probe := range pending {
				probe.future.Cancel()
			}
			return result, submission.Err
		}
		pending = append(pending, pendingProbe{tag: candidate.PrimaryTag, future: submission.Future})
	}
	for index, probe := range pending {
		probeResult, err := probe.future.Await(ctx)
		if err != nil {
			for _, remaining := range pending[index+1:] {
				remaining.future.Cancel()
			}
			return result, err
		}
		if probeResult.Outcome == OutcomeSuccess {
			result[probe.tag] = uint16(max(0, probeResult.Delay.Milliseconds()))
		}
	}
	return result, nil
}

func (p *AdaptivePool) TriggerAdaptiveProbe(ctx context.Context) error {
	p.lifecycleAccess.Lock()
	scheduler := p.scheduler
	p.lifecycleAccess.Unlock()
	if scheduler == nil {
		return errors.New("adaptive probe scheduler is not running")
	}
	snapshot := p.catalog.load()
	if snapshot == nil {
		return ErrNoCandidates
	}
	for _, candidate := range snapshot.Candidates {
		if err := ctx.Err(); err != nil {
			return err
		}
		submission := scheduler.Submit(p.probeTask(snapshot, candidate, time.Now(), 0))
		if submission.Err != nil {
			return submission.Err
		}
	}
	return nil
}

func (p *AdaptivePool) TriggerAdaptiveCapabilityProbe(ctx context.Context) error {
	p.lifecycleAccess.Lock()
	controllers := cloneCapabilityControllers(p.capabilityControllers)
	if len(controllers) == 0 && p.capabilityController != nil {
		controllers = map[string]*CapabilityProbeController{youtubeProbeServiceID: p.capabilityController}
	}
	p.lifecycleAccess.Unlock()
	if len(controllers) == 0 {
		return adapter.ErrAdaptiveCapabilityUnavailable
	}
	for _, serviceID := range sortedCapabilityControllerIDs(controllers) {
		_, err := controllers[serviceID].RunOnce(ctx)
		if errors.Is(err, ErrCapabilityCycleBusy) {
			return adapter.ErrAdaptiveCapabilityBusy
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *AdaptivePool) AdaptiveStatus() adapter.AdaptivePoolStatus {
	snapshot := p.catalog.load()
	status := adapter.AdaptivePoolStatus{Shadow: p.shadow, UpdatedAt: time.Now()}
	status.MissedObservations = p.missedObservations.Load()
	status.ObservationStaleTotal = p.observationStale.Load()
	status.ObservationDuplicateTotal = p.observationDuplicate.Load()
	status.ObservationBackpressureTotal = p.observationBackpressure.Load()
	status.ObservationReducerFailureTotal = p.observationReducerFailure.Load()
	status.ObservationIdentityFailureTotal = p.observationIdentityFailure.Load()
	status.ObservationPanicTotal = p.observationPanic.Load()
	status.ObservationPermitBusyTotal = p.observationPermitBusy.Load()
	status.BusinessTLSFailuresTotal = p.businessTLSFailures.Load()
	status.TransportFailuresTotal = p.transportFailures.Load()
	status.RecentSwitches, status.SelectionSwitchesTotal = p.switchAudit.Snapshot()
	status.DeltaAppliedTotal = p.deltaAppliedTotal.Load()
	status.DeltaFallbackTotal = p.deltaFallbackTotal.Load()
	if p.control == nil {
		p.control = new(ControlState)
	}
	p.control.access.RLock()
	status.Pinned = p.control.pinnedTag
	if p.shadow {
		status.Mode = "shadow"
	} else if p.control.pinned != (NodeID{}) {
		status.Mode = string(ModeManual)
	} else {
		status.Mode = string(p.defaultMode)
	}
	p.control.access.RUnlock()
	status.ActiveLeases, status.LeaseEvictions = p.leases.Stats()
	status.BulkSequence = p.control.bulkSequence.Load()
	status.ControlRevision = p.control.revision.Load()
	if p.resolver != nil {
		status.ServiceOverrideCount = len(p.resolver.Overrides(time.Now()))
	}
	if p.catalog != nil {
		bindings := p.catalog.BindingStats()
		status.ActiveBindingCount = bindings.Active
		status.RetiredBindingCount = bindings.Retired
	}
	if snapshot == nil {
		return status
	}
	leaseSnapshot := p.leases.PersistenceSnapshot(time.Now())
	slices.SortFunc(leaseSnapshot, func(left, right SessionLease) int {
		if left.ServiceID != right.ServiceID {
			return bytes.Compare([]byte(left.ServiceID), []byte(right.ServiceID))
		}
		return bytes.Compare(left.NodeID[:], right.NodeID[:])
	})
	for _, lease := range leaseSnapshot {
		if len(status.ServiceLeases) >= statusCandidateLimit {
			break
		}
		tag := ""
		if candidate, loaded := snapshot.Candidate(lease.NodeID); loaded && candidate.Handle.Slot == lease.NodeSlot && candidate.Handle.Version == lease.NodeVersion {
			tag = safePersistentTag(candidate.PrimaryTag)
		}
		status.ServiceLeases = append(status.ServiceLeases, adapter.AdaptiveServiceLease{
			ServiceID: lease.ServiceID, Mode: string(lease.Mode), NodeID: lease.NodeID.String(), Tag: tag,
			ExpiresAt: lease.ExpiresAt, UpdatedAt: lease.UpdatedAt,
		})
	}
	status.Generation = snapshot.Generation
	status.CandidateCount = len(snapshot.Candidates)
	status.DuplicatesSuppressed = snapshot.DuplicatesSuppressed
	status.StableIdentityCount = snapshot.StableIdentityCount
	for _, candidate := range snapshot.Candidates {
		if candidate.EndpointConflictCount > 1 {
			status.EndpointConflictCount++
		}
	}
	throughput := p.health.ThroughputByHandle()
	for _, candidate := range snapshot.Candidates {
		status.AliasCount += len(candidate.Aliases)
	}
	if len(snapshot.Candidates) > statusCandidateLimit {
		status.Candidates = make([]adapter.AdaptiveCandidateStatus, 0, statusCandidateLimit)
	} else {
		status.Candidates = make([]adapter.AdaptiveCandidateStatus, 0, len(snapshot.Candidates))
	}
	for _, candidate := range snapshot.Candidates {
		if len(status.Candidates) >= statusCandidateLimit {
			break
		}
		health := p.health.EndpointHandle(candidate.Handle)
		throughputStatus := throughput[candidate.Handle]
		state := string(health.Health)
		if health.Breaker != BreakerClosed {
			state = string(health.Breaker)
		}
		status.Candidates = append(status.Candidates, adapter.AdaptiveCandidateStatus{
			NodeID:                candidate.ID.String(),
			EndpointID:            candidate.EndpointID.String(),
			EndpointConflictCount: candidate.EndpointConflictCount,
			NodeSlot:              candidate.Handle.Slot,
			NodeVersion:           candidate.Handle.Version,
			Tag:                   candidate.PrimaryTag,
			Weight:                p.nodeWeights.Weight(candidate.PrimaryTag),
			Aliases:               append([]string(nil), candidate.Aliases...),
			IdentityStable:        candidate.IdentityStable,
			State:                 state,
			Health:                string(health.Health),
			Breaker:               string(health.Breaker),
			LastProbeAt:           health.LastUpdated,
			LastProbeDelay:        uint16(max(0, health.LastDelay.Milliseconds())),
			ThroughputBPS:         throughputStatus.BPS,
			ThroughputSamples:     throughputStatus.Samples,
			Successes:             health.Successes,
			Failures:              health.Failures,
			EvidenceWeight:        health.EvidenceWeight,
			OpenUntil:             health.CooldownUntil,
			Reason:                health.Reason,
		})
	}
	status.StateEntries, status.StateEvictions = p.health.Stats()
	status.StatePersistenceFailures = p.statePersistenceFailures.Load()
	p.lifecycleAccess.Lock()
	scheduler := p.scheduler
	capabilityControllers := cloneCapabilityControllers(p.capabilityControllers)
	if len(capabilityControllers) == 0 && p.capabilityController != nil {
		capabilityControllers = map[string]*CapabilityProbeController{youtubeProbeServiceID: p.capabilityController}
	}
	capabilityEnabled := p.capabilityProvider != nil
	capabilityProvider := p.capabilityProvider
	p.lifecycleAccess.Unlock()
	status.CapabilityEnabled = capabilityEnabled
	status.CapabilityInitFailures = p.capabilityInitFailures.Load()
	status.ExitIdentityBaselines, status.ExitIdentityChangesTotal, status.ExitIdentitySaturatedNodes = p.exitIdentityStore.Stats()
	for _, serviceID := range sortedCapabilityControllerIDs(capabilityControllers) {
		capabilityStatus := capabilityControllers[serviceID].Status()
		status.CapabilityRunning = status.CapabilityRunning || capabilityStatus.Running
		status.CapabilityCyclesStarted += capabilityStatus.CyclesStarted
		status.CapabilityCyclesCompleted += capabilityStatus.CyclesCompleted
		status.CapabilityRefreshFailures += capabilityStatus.RefreshFailures
		status.CapabilityViewFailures += capabilityStatus.ViewFailures
		status.CapabilitySuiteFailures += capabilityStatus.SuiteFailures
		if capabilityStatus.LastFailureStage != "" {
			status.CapabilityLastFailureStage = serviceID + ":" + capabilityStatus.LastFailureStage
		}
	}
	if capabilityProvider != nil {
		if targetSnapshot, targetErr := capabilityProvider.Snapshot(context.Background(), youtubeProbeServiceID); targetErr == nil {
			status.CapabilityTargetGeneration = targetSnapshot.Generation
		}
	}
	if scheduler != nil {
		status.ProbeQueueDepth, _, _ = scheduler.Stats()
	}
	if p.schedulerOwner != nil {
		owner, generation, accepted, coalesced, deferred, rejected, completed, stalled := p.schedulerOwner.Stats()
		status.ProbeOwnerEpoch = uint64(owner)
		status.ProbeOwnerGeneration = generation
		status.ProbeAcceptedTotal = accepted
		status.ProbeCoalescedTotal = coalesced
		status.ProbeDeferredTotal = deferred
		status.ProbeRejectedTotal = rejected
		status.ProbeCompletedTotal = completed
		status.ProbeSchedulerStalledTotal = stalled
	}
	return status
}

func (p *AdaptivePool) onSourceUpdated() error {
	if p.closing.Load() {
		return nil
	}
	p.lifecycleAccess.Lock()
	phase := p.publishPhase
	if phase == publishPhasePrepared || phase == publishPhasePublishing {
		p.sourceDirty = true
		p.lifecycleAccess.Unlock()
		return nil
	}
	retired := p.retired || phase == publishPhaseRollingBack || phase == publishPhaseRetired
	p.lifecycleAccess.Unlock()
	if retired {
		return nil
	}
	return p.rebuild()
}

func (p *AdaptivePool) rebuild() error {
	p.catalogAccess.Lock()
	defer p.catalogAccess.Unlock()
	generation := p.generation.Add(1)
	var source SourcePublication
	var err error
	if p.sourcePublication != nil {
		if incremental, loaded := p.source.(IncrementalSourceRuntime); loaded {
			var delta SourceDeltaPublication
			delta, err = incremental.Delta(p.ctx, generation)
			if err == nil {
				source, err = ApplySourceDelta(*p.sourcePublication, delta)
				if err == nil {
					p.deltaAppliedTotal.Add(1)
				}
			}
			if err != nil {
				err = nil
			}
		}
	}
	if source.Generation == 0 && err == nil {
		source, err = p.source.Snapshot(p.ctx, generation)
		if p.sourcePublication != nil {
			p.deltaFallbackTotal.Add(1)
		}
	}
	if err != nil {
		return err
	}
	clonedSource := cloneSourcePublication(source)
	p.sourcePublication = &clonedSource
	identitySource, err := IdentityFromSource(source.SourceSnapshot)
	if err != nil {
		return err
	}
	p.lifecycleAccess.Lock()
	published := p.published
	p.lifecycleAccess.Unlock()
	if !published {
		preparedIdentity, prepareErr := p.runtimeManager.PrepareEpoch(p.groupID, p.health, p.leases, p.control, identitySource)
		if prepareErr != nil {
			return prepareErr
		}
		preparedExecution, prepareErr := p.catalog.PrepareCommitted(source, preparedIdentity.Identity())
		if prepareErr != nil {
			return prepareErr
		}
		if prepareErr = p.persistPreparedIdentityKey(); prepareErr != nil {
			return prepareErr
		}
		p.preparedIdentity = preparedIdentity
		p.preparedExecution = preparedExecution
		p.lifecycleAccess.Lock()
		p.publishPhase = publishPhasePrepared
		p.lifecycleAccess.Unlock()
		return nil
	}
	preparedIdentity, err := p.runtimeManager.PrepareRevision(p.groupID, p.runtimeIdentity.EpochID, identitySource)
	if err != nil {
		return err
	}
	preparedExecution, err := p.catalog.PrepareCommitted(source, preparedIdentity.Identity())
	if err != nil {
		return err
	}
	previous := p.catalog.load()
	_, identity, err := preparedIdentity.Commit()
	if err != nil {
		return err
	}
	if err = p.persistStateDurable(); err != nil {
		_ = preparedIdentity.Rollback()
		return errors.New("adaptive identity revision is not durable")
	}
	next := p.catalog.CommitPrepared(preparedExecution)
	p.runtimeIdentity = identity
	p.applyCommittedTransitions(identity)
	p.reconcileScheduler(previous, next)
	return nil
}

func (p *AdaptivePool) persistPreparedIdentityKey() error {
	if !p.identityKeyNew {
		return nil
	}
	if err := persistIdentityKey(p.statePath+".key", p.identityKey[:]); err != nil {
		return E.Cause(err, "persist adaptive identity key")
	}
	p.identityKeyNew = false
	return nil
}

func (p *AdaptivePool) startSchedulerLocked() {
	if !p.published || !p.postStarted || p.retired || p.scheduler != nil {
		return
	}
	if p.schedulerOwner == nil {
		p.schedulerOwner = p.runtimeManager.SchedulerCoordinator(p.groupID)
	}
	snapshot := p.catalog.load()
	if snapshot == nil || snapshot.RuntimeEpochID == 0 {
		return
	}
	ownership, err := p.schedulerOwner.Claim(snapshot.RuntimeEpochID)
	if err != nil {
		return
	}
	p.schedulerGen = ownership.Generation
	p.scheduler = newOwnedProbeScheduler(p.ctx, p.schedulerOwner, ownership, p.probeConcurrency, p.probeQueueSize)
	for _, task := range p.startupProbeTasks(snapshot, time.Now()) {
		_ = p.scheduler.Submit(task)
	}
	p.startCapabilityControllerLocked(snapshot)
}

func (p *AdaptivePool) startCapabilityControllerLocked(snapshot *ExecutionSnapshot) {
	if p.capabilityProvider == nil || len(p.capabilityControllers) != 0 || p.capabilityController != nil || p.scheduler == nil || snapshot == nil || snapshot.RuntimeEpochID == 0 {
		return
	}
	refresh := p.capabilityRefresh
	if refresh <= 0 {
		refresh = defaultCapabilityRefresh
	}
	timeout := p.capabilityTimeout
	if timeout <= 0 {
		timeout = defaultCapabilityTimeout
	}
	quorum := p.capabilityQuorum
	if quorum <= 0 {
		quorum = 2
	}
	commonModeMin := p.capabilityCommonModeMin
	if commonModeMin <= 0 {
		commonModeMin = 2
	}
	runner := p.capabilityRunner
	if runner == nil {
		runner = NewCapabilityProbeRunner(nil)
	}
	sessions, err := NewRuntimeCapabilityObservationFactory(p.runtimeManager, p.groupID, p.sharedObservationIngestor(), p.health, p.observationReducerHook)
	if err != nil {
		p.capabilityInitFailures.Add(1)
		return
	}
	serviceIDs := append([]string(nil), p.capabilityServiceIDs...)
	if len(serviceIDs) == 0 {
		serviceIDs = []string{youtubeProbeServiceID}
	}
	controllers := make(map[string]*CapabilityProbeController, len(serviceIDs))
	parent := p.ctx
	if parent == nil {
		parent = context.Background()
	}
	for _, serviceID := range serviceIDs {
		suite, err := NewCapabilityProbeSuite(nil, p.scheduler, p.capabilityProvider, runner, NewProbeAggregator(ProbeAggregatorConfig{}, nil, nil), sessions, p.exitIdentityStore)
		if err != nil {
			p.capabilityInitFailures.Add(1)
			closeCapabilityControllers(controllers)
			return
		}
		controller, err := NewCapabilityProbeController(nil, p.capabilityProvider, suite, p.catalog.Snapshot, snapshot.RuntimeEpochID, refresh, timeout, quorum, commonModeMin, p.catalog)
		if err != nil {
			p.capabilityInitFailures.Add(1)
			closeCapabilityControllers(controllers)
			return
		}
		controller.WithServiceID(serviceID)
		if err = controller.Start(parent); err != nil {
			controller.Close()
			p.capabilityInitFailures.Add(1)
			closeCapabilityControllers(controllers)
			return
		}
		controllers[serviceID] = controller
	}
	p.capabilityControllers = controllers
	p.capabilityController = controllers[youtubeProbeServiceID]
}

func cloneCapabilityControllers(source map[string]*CapabilityProbeController) map[string]*CapabilityProbeController {
	cloned := make(map[string]*CapabilityProbeController, len(source))
	for serviceID, controller := range source {
		cloned[serviceID] = controller
	}
	return cloned
}

func sortedCapabilityControllerIDs(controllers map[string]*CapabilityProbeController) []string {
	serviceIDs := make([]string, 0, len(controllers))
	for serviceID := range controllers {
		serviceIDs = append(serviceIDs, serviceID)
	}
	slices.Sort(serviceIDs)
	return serviceIDs
}

func closeCapabilityControllers(controllers map[string]*CapabilityProbeController) {
	for _, controller := range controllers {
		controller.Close()
	}
}

func (p *AdaptivePool) reconcileScheduler(previous, next *ExecutionSnapshot) {
	p.lifecycleAccess.Lock()
	scheduler := p.scheduler
	p.lifecycleAccess.Unlock()
	if scheduler == nil {
		return
	}
	if previous != nil {
		scheduler.RemoveRevision(previous.RuntimeEpochID, previous.CatalogRevision)
	}
	for _, task := range p.startupProbeTasks(next, time.Now()) {
		_ = scheduler.Submit(task)
	}
}

func (p *AdaptivePool) startupProbeTasks(snapshot *ExecutionSnapshot, now time.Time) []ProbeTask {
	if snapshot == nil || len(snapshot.Candidates) == 0 {
		return nil
	}
	candidates := slices.Clone(snapshot.Candidates)
	slices.SortFunc(candidates, func(left, right Candidate) int {
		if compared := bytes.Compare(left.ID[:], right.ID[:]); compared != 0 {
			return compared
		}
		if left.Handle.Slot < right.Handle.Slot {
			return -1
		}
		if left.Handle.Slot > right.Handle.Slot {
			return 1
		}
		if left.Handle.Version < right.Handle.Version {
			return -1
		}
		if left.Handle.Version > right.Handle.Version {
			return 1
		}
		return 0
	})

	immediate := min(max(p.probeConcurrency, 1), len(candidates))
	spreadCount := len(candidates) - immediate
	spread := p.probeCoverage / 10
	if spread > 30*time.Second {
		spread = 30 * time.Second
	}
	if spread < 0 {
		spread = 0
	}
	tasks := make([]ProbeTask, 0, len(candidates))
	for index, candidate := range candidates {
		dueAt := now
		if index >= immediate && spreadCount > 0 {
			dueAt = now.Add(time.Duration(index-immediate+1) * spread / time.Duration(spreadCount))
		}
		tasks = append(tasks, p.probeTask(snapshot, candidate, dueAt, p.probeCoverage))
	}
	return tasks
}

func (p *AdaptivePool) runGenericProbe(ctx context.Context, snapshot *ExecutionSnapshot, candidate Candidate) (ProbeResult, uint16) {
	current := p.catalog.load()
	if current == nil || snapshot == nil || current.RuntimeEpochID != snapshot.RuntimeEpochID || current.CatalogRevision != snapshot.CatalogRevision || current.Generation != snapshot.Generation {
		return ProbeResult{Outcome: OutcomeDeferred, Reason: "catalog revision unavailable"}, 0
	}
	currentCandidate, loaded := current.Candidate(candidate.ID)
	if !loaded || currentCandidate.Handle.Slot != candidate.Handle.Slot || currentCandidate.Handle.Version != candidate.Handle.Version {
		return ProbeResult{Outcome: OutcomeDeferred, Reason: "candidate handle retired"}, 0
	}
	permit, allowed := p.health.TryAcquireDomainPermitHandle(candidate.Handle, DomainEndpoint, "", "", time.Now())
	if !allowed {
		return ProbeResult{Outcome: OutcomeDeferred, Reason: "endpoint breaker deferred"}, 0
	}
	var attempt *observationAttempt
	var err error
	if current.RuntimeEpochID != 0 && current.CatalogRevision != 0 && p.runtimeManager != nil {
		attempt, err = p.beginObservationAttempt(current, currentCandidate, permit, N.NetworkTCP)
		if err != nil {
			permit.ReleaseDeferred()
			return ProbeResult{Outcome: OutcomeDeferred, Reason: err.Error()}, 0
		}
	}
	startedAt := time.Now()
	execution, loaded := p.catalog.AcquireExecution(ExecutionToken{RuntimeEpochID: current.RuntimeEpochID, CatalogRevision: current.CatalogRevision, Handle: currentCandidate.Handle})
	if !loaded {
		p.completeGenericProbe(attempt, ErrExecutionBindingUnavailable, time.Since(startedAt), true)
		return ProbeResult{Outcome: OutcomeDeferred, Reason: ErrExecutionBindingUnavailable.Error(), Settled: true}, 0
	}
	delay, probeErr := p.runProbe(ctx, execution.Port)
	execution.Release()
	elapsed := time.Since(startedAt)
	latest := p.catalog.load()
	latestCandidate, stillActive := Candidate{}, false
	if latest != nil {
		latestCandidate, stillActive = latest.Candidate(candidate.ID)
	}
	stale := latest == nil || latest.RuntimeEpochID != snapshot.RuntimeEpochID || latest.CatalogRevision != snapshot.CatalogRevision || latest.Generation != snapshot.Generation || !stillActive || latestCandidate.Handle.Slot != candidate.Handle.Slot || latestCandidate.Handle.Version != candidate.Handle.Version
	deferred := stale || !p.probeOwnerActive() || (p.ctx != nil && p.ctx.Err() != nil) || (ctx.Err() != nil && !errors.Is(ctx.Err(), context.DeadlineExceeded))
	if attempt == nil {
		permit.ReleaseDeferred()
	} else {
		p.completeGenericProbe(attempt, probeErr, elapsed, deferred)
	}
	if deferred {
		return ProbeResult{Outcome: OutcomeDeferred, Delay: elapsed, Reason: "probe identity retired", Settled: attempt != nil}, delay
	}
	if probeErr != nil {
		return ProbeResult{Outcome: OutcomeFailure, Delay: elapsed, Reason: probeErr.Error(), Settled: attempt != nil}, delay
	}
	return ProbeResult{Outcome: OutcomeSuccess, Delay: time.Duration(delay) * time.Millisecond, Settled: attempt != nil}, delay
}

func (p *AdaptivePool) probeOwnerActive() bool {
	p.lifecycleAccess.Lock()
	scheduler := p.scheduler
	p.lifecycleAccess.Unlock()
	return scheduler == nil || scheduler.ActiveOwner()
}

func (p *AdaptivePool) completeGenericProbe(attempt *observationAttempt, probeErr error, delay time.Duration, deferred bool) {
	defer attempt.lease.Release()
	evidence := attempt.evidence
	evidence.Source = SourceProbe
	evidence.Stage = StageProxyTunnel
	// A single external target is useful quality evidence, but it cannot
	// distinguish a node failure from common-mode target failure or blocking.
	evidence.Confidence = ConfidenceMedium
	evidence.Delay = delay
	evidence.At = time.Now()
	evidence.Reason = errorReason(probeErr)
	switch {
	case deferred:
		evidence.Outcome, evidence.Failure = OutcomeDeferred, FailureCanceled
	case probeErr == nil:
		evidence.Outcome, evidence.Failure = OutcomeSuccess, FailureNone
	case errors.Is(probeErr, context.DeadlineExceeded):
		evidence.Outcome, evidence.Failure = OutcomeFailure, FailureTimeout
	default:
		evidence.Outcome, evidence.Failure = OutcomeFailure, FailureConnect
	}
	disposition, publishErr := PublishSettledObservationGuarded(p.sharedObservationIngestor(), attempt.guard, evidence, attempt.reducer)
	p.recordObservationResult(disposition, publishErr)
}

func (p *AdaptivePool) probeTask(snapshot *ExecutionSnapshot, candidate Candidate, dueAt time.Time, interval time.Duration) ProbeTask {
	priority := ProbePriorityOnDemand
	failureInterval := time.Duration(0)
	if interval > 0 {
		priority = ProbePriorityCoverage
		failureInterval = interval / 4
		if failureInterval > time.Minute {
			failureInterval = time.Minute
		}
		if failureInterval <= 0 {
			failureInterval = interval
		}
	}
	return ProbeTask{
		Key: ProbeKey{
			RuntimeEpochID: snapshot.RuntimeEpochID, CatalogRevision: snapshot.CatalogRevision, SourceGeneration: snapshot.Generation,
			NodeID: candidate.ID, NodeSlot: candidate.Handle.Slot, NodeVersion: candidate.Handle.Version, Suite: "generic-http", Target: p.probeURL,
		},
		Source:          firstOrDefault(candidate.Sources, "static"),
		Priority:        priority,
		DueAt:           dueAt,
		Interval:        interval,
		FailureInterval: failureInterval,
		Timeout:         p.probeTimeout,
		Run: func(ctx context.Context) ProbeResult {
			result, _ := p.runGenericProbe(ctx, snapshot, candidate)
			return result
		},
	}
}

func (p *AdaptivePool) applyCommittedTransitions(identity RuntimeIdentity) {
	if identity.Revision == 0 {
		return
	}
	for {
		applied := p.appliedRevision.Load()
		if uint64(identity.Revision) <= applied {
			return
		}
		if p.appliedRevision.CompareAndSwap(applied, uint64(identity.Revision)) {
			break
		}
	}
	for _, handle := range identity.RetiredHandles {
		p.health.RetireNodeHandle(handle)
		p.leases.RetireNodeHandle(handle)
		p.lifecycleAccess.Lock()
		scheduler := p.scheduler
		p.lifecycleAccess.Unlock()
		if scheduler != nil {
			scheduler.RemoveHandle(handle)
		}
	}
}

func (p *AdaptivePool) runProbe(ctx context.Context, candidate N.Dialer) (uint16, error) {
	if p.probeRunner == nil {
		return urltest.URLTest(ctx, p.probeURL, candidate)
	}
	return p.probeRunner(ctx, p.probeURL, candidate)
}

func (p *AdaptivePool) pinnedNodeID() *NodeID {
	if p.control == nil {
		return nil
	}
	p.control.access.RLock()
	pinned := p.control.pinned
	p.control.access.RUnlock()
	if pinned == (NodeID{}) {
		return nil
	}
	return &pinned
}

func (p *AdaptivePool) setLatest(tag string) {
	if p.control == nil {
		p.control = new(ControlState)
	}
	p.control.access.Lock()
	p.control.latestTag = tag
	p.control.access.Unlock()
}

func (p *AdaptivePool) leaseTTL(mode PolicyMode) time.Duration {
	if mode == ModeStrictAffinity {
		return p.strictLeaseTTL
	}
	return p.adaptiveLeaseTTL
}

func loadOrPrepareIdentityKey(path string) ([32]byte, bool, error) {
	var key [32]byte
	content, err := os.ReadFile(path)
	if err == nil {
		if len(content) != len(key) {
			return key, false, errors.New("invalid adaptive identity key length")
		}
		copy(key[:], content)
		return key, false, nil
	}
	if !os.IsNotExist(err) {
		return key, false, err
	}
	if _, err = rand.Read(key[:]); err != nil {
		return key, false, err
	}
	return key, true, nil
}

func persistIdentityKey(path string, key []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".adaptive-key-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err = temporary.Chmod(0o600); err == nil {
		_, err = temporary.Write(key)
	}
	if err == nil {
		err = temporary.Sync()
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(temporaryPath, path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	err = directory.Sync()
	if closeErr := directory.Close(); err == nil {
		err = closeErr
	}
	return err
}

func safeFileName(value string) string {
	if value == "" {
		return "default"
	}
	result := make([]rune, 0, len(value))
	for _, character := range value {
		switch {
		case character >= 'a' && character <= 'z', character >= 'A' && character <= 'Z', character >= '0' && character <= '9', character == '-', character == '_':
			result = append(result, character)
		default:
			result = append(result, '_')
		}
	}
	return string(result)
}

func firstOrDefault(values []string, fallback string) string {
	if len(values) == 0 || values[0] == "" {
		return fallback
	}
	return values[0]
}

func parseCapabilityTrustedKeys(encoded map[string]string) (map[string]ed25519.PublicKey, error) {
	if len(encoded) == 0 {
		return nil, errors.New("adaptive capability trusted keys are required")
	}
	keys := make(map[string]ed25519.PublicKey, len(encoded))
	for keyID, value := range encoded {
		decoded, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			return nil, errors.New("adaptive capability trusted key is invalid")
		}
		keys[keyID] = ed25519.PublicKey(decoded)
	}
	return cloneProbeTargetKeyring(keys)
}
