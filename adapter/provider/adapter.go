package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/batch"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
)

type Adapter struct {
	ctx             context.Context
	outbound        adapter.OutboundManager
	endpoint        adapter.EndpointManager
	router          adapter.Router
	logFactory      log.Factory
	logger          log.ContextLogger
	providerType    string
	providerTag     string
	outboundsAccess sync.RWMutex
	outbounds       []adapter.Outbound
	outboundsByTag  map[string]adapter.Outbound
	endpoints       []adapter.Outbound
	endpointsByTag  map[string]adapter.Outbound
	ticker          *time.Ticker
	checking        atomic.Bool
	paused          atomic.Bool
	history         *urltest.HistoryStorage
	callbackAccess  sync.Mutex
	callbacks       list.List[adapter.ProviderUpdateCallback]
	deltaAccess     sync.RWMutex
	deltaRevision   uint64
	deltaHistory    []adapter.ProviderDelta

	link     string
	enabled  bool
	timeout  time.Duration
	interval time.Duration
}

const providerDeltaHistoryLimit = 16

func NewAdapter(ctx context.Context, router adapter.Router, outbound adapter.OutboundManager, endpoint adapter.EndpointManager, logFactory log.Factory, logger log.ContextLogger, providerTag string, providerType string, options option.ProviderHealthCheckOptions) Adapter {
	timeout := time.Duration(options.Timeout)
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	interval := time.Duration(options.Interval)
	if interval == 0 {
		interval = 10 * time.Minute
	}
	if interval < time.Minute {
		interval = time.Minute
	}
	return Adapter{
		ctx:          ctx,
		outbound:     outbound,
		endpoint:     endpoint,
		router:       router,
		logFactory:   logFactory,
		logger:       logger,
		providerType: providerType,
		providerTag:  providerTag,

		enabled:  options.Enabled,
		link:     options.URL,
		timeout:  timeout,
		interval: interval,
	}
}

// stripTCPFastOpenForAnyTLS clears dialer TFO on anytls outbounds so create
// does not fail on pure SagerNet (anytls rejects tcp_fast_open).
func stripTCPFastOpenForAnyTLS(outbound option.Outbound) option.Outbound {
	if outbound.Type != C.TypeAnyTLS {
		return outbound
	}
	switch opts := outbound.Options.(type) {
	case *option.AnyTLSOutboundOptions:
		if opts != nil && opts.TCPFastOpen {
			clone := *opts
			clone.TCPFastOpen = false
			outbound.Options = &clone
		}
	case option.AnyTLSOutboundOptions:
		if opts.TCPFastOpen {
			opts.TCPFastOpen = false
			outbound.Options = &opts
		}
	default:
		if w, ok := outbound.Options.(option.DialerOptionsWrapper); ok {
			d := w.TakeDialerOptions()
			if d.TCPFastOpen {
				d.TCPFastOpen = false
				w.ReplaceDialerOptions(d)
			}
		}
	}
	return outbound
}

func (a *Adapter) Start() error {
	a.history = service.PtrFromContext[urltest.HistoryStorage](a.ctx)
	if a.history == nil {
		return E.New("missing URL test history storage")
	}
	if a.enabled {
		a.ticker = time.NewTicker(a.interval)
		go a.loopCheck()
	}
	return nil
}

func (a *Adapter) Type() string {
	return a.providerType
}

func (a *Adapter) Tag() string {
	return a.providerTag
}

func (a *Adapter) Outbounds() []adapter.Outbound {
	a.outboundsAccess.RLock()
	defer a.outboundsAccess.RUnlock()
	outbounds := make([]adapter.Outbound, 0, len(a.outbounds)+len(a.endpoints))
	outbounds = append(outbounds, a.outbounds...)
	outbounds = append(outbounds, a.endpoints...)
	return outbounds
}

func (a *Adapter) Outbound(tag string) (adapter.Outbound, bool) {
	a.outboundsAccess.RLock()
	defer a.outboundsAccess.RUnlock()
	if detour, ok := a.outboundsByTag[tag]; ok {
		return detour, true
	}
	detour, ok := a.endpointsByTag[tag]
	return detour, ok
}

func (a *Adapter) resolveOutboundTags(newOpts []option.Outbound) []string {
	tags := make([]string, len(newOpts))
	seen := make(map[string]bool)
	for i, opt := range newOpts {
		var baseTag string
		if opt.Tag != "" {
			baseTag = F.ToString(a.providerTag, "/", opt.Tag)
		} else {
			baseTag = F.ToString(a.providerTag, "/", i)
		}
		tag := uniqueProviderTag(baseTag, providerOutboundIdentity(opt), seen)
		if tag != baseTag {
			a.logger.Warn("duplicate outbound tag ", baseTag, " in provider, renamed to ", tag)
		}
		seen[tag] = true
		tags[i] = tag
	}
	return tags
}

// providerOutboundIdentity fingerprints an outbound for stable duplicate rename
// across provider reloads (order-independent). Avoids " (2)" churn that breaks
// smart pins/filters when the subscription list reorders.
func providerOutboundIdentity(opt option.Outbound) string {
	return providerOptionFingerprint(opt.Type, opt.Tag, opt.Options)
}

// providerOptionFingerprint uses encoding/json instead of fmt's structural
// formatting. JSON sorts map keys and therefore keeps duplicate suffixes
// stable when a provider refresh changes map iteration order.
func providerOptionFingerprint(kind, tag string, options any) string {
	payload, err := json.Marshal(struct {
		Kind    string `json:"kind"`
		Tag     string `json:"tag"`
		Options any    `json:"options"`
	}{Kind: kind, Tag: tag, Options: options})
	if err != nil {
		payload = []byte(F.ToString(kind, "\x00", tag))
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:4])
}

func uniqueProviderTag(baseTag, identity string, seen map[string]bool) string {
	if !seen[baseTag] {
		return baseTag
	}
	if identity != "" {
		stable := F.ToString(baseTag, " #", identity)
		if !seen[stable] {
			return stable
		}
	}
	for n := 2; ; n++ {
		tag := F.ToString(baseTag, " (", n, ")")
		if !seen[tag] {
			return tag
		}
	}
}

func (a *Adapter) UpdateOutbounds(oldOpts []option.Outbound, newOpts []option.Outbound) {
	newTags := a.resolveOutboundTags(newOpts)
	var (
		oldOptByTag    = make(map[string]option.Outbound)
		outbounds      = make([]adapter.Outbound, 0, len(newOpts))
		outboundsByTag = make(map[string]adapter.Outbound)
	)
	for _, opt := range oldOpts {
		oldOptByTag[opt.Tag] = opt
	}
	activeTags := a.activeOutboundTags()
	previousOutbounds := a.activeOutboundSnapshot()
	a.removeUseless(newTags)
	for i, opt := range newOpts {
		tag := newTags[i]
		outbound, exist := a.outbound.Outbound(tag)
		_, active := activeTags[tag]
		previousOutbound := outbound
		if !exist || !active || !reflect.DeepEqual(opt, oldOptByTag[opt.Tag]) {
			opt = stripTCPFastOpenForAnyTLS(opt)
			err := a.outbound.Create(
				adapter.WithContext(a.ctx, &adapter.InboundContext{
					Outbound: tag,
				}),
				a.router,
				a.logFactory.NewLogger(F.ToString("outbound/", opt.Type, "[", tag, "]")),
				tag,
				opt.Type,
				opt.Options,
			)
			if err != nil {
				a.logger.Warn(err, " in ", tag, ", skip create this outbound")
				// Keep the currently active instance on refresh failure. Removing it
				// here turns a transient parse/start error into an avoidable outage.
				if active && previousOutbound != nil {
					outbounds = append(outbounds, previousOutbound)
					outboundsByTag[tag] = previousOutbound
				}
				continue
			}
			outbound, _ = a.outbound.Outbound(tag)
		}
		if outbound == nil {
			a.logger.Warn("outbound ", tag, " was not registered after create, keeping previous snapshot")
			if active && previousOutbound != nil {
				outbounds = append(outbounds, previousOutbound)
				outboundsByTag[tag] = previousOutbound
			}
			continue
		}
		outbounds = append(outbounds, outbound)
		outboundsByTag[tag] = outbound
	}
	a.outboundsAccess.Lock()
	a.outbounds = outbounds
	a.outboundsByTag = outboundsByTag
	a.outboundsAccess.Unlock()
	a.recordOutboundDelta(previousOutbounds, outboundsByTag)
	if a.enabled && a.history != nil {
		go a.HealthCheck(a.ctx)
	}
}

func (a *Adapter) activeOutboundSnapshot() map[string]adapter.Outbound {
	a.outboundsAccess.RLock()
	defer a.outboundsAccess.RUnlock()
	snapshot := make(map[string]adapter.Outbound, len(a.outbounds))
	for _, outbound := range a.outbounds {
		if outbound != nil {
			snapshot[outbound.Tag()] = outbound
		}
	}
	return snapshot
}

func (a *Adapter) recordOutboundDelta(previous, current map[string]adapter.Outbound) {
	upserts := make([]string, 0)
	removes := make([]string, 0)
	for tag, oldOutbound := range previous {
		if next, loaded := current[tag]; !loaded || next == nil {
			removes = append(removes, tag)
		} else if next != oldOutbound {
			upserts = append(upserts, tag)
		}
	}
	for tag, next := range current {
		if _, loaded := previous[tag]; !loaded && next != nil {
			upserts = append(upserts, tag)
		}
	}
	if len(upserts) == 0 && len(removes) == 0 {
		return
	}
	slices.Sort(upserts)
	slices.Sort(removes)
	a.deltaAccess.Lock()
	base := a.deltaRevision
	a.deltaRevision++
	a.deltaHistory = append(a.deltaHistory, adapter.ProviderDelta{
		BaseRevision: base,
		Revision:     a.deltaRevision,
		Upserts:      upserts,
		Removes:      removes,
	})
	if len(a.deltaHistory) > providerDeltaHistoryLimit {
		a.deltaHistory = a.deltaHistory[len(a.deltaHistory)-providerDeltaHistoryLimit:]
	}
	a.deltaAccess.Unlock()
}

func (a *Adapter) OutboundDeltaRevision() uint64 {
	a.deltaAccess.RLock()
	defer a.deltaAccess.RUnlock()
	return a.deltaRevision
}

func (a *Adapter) OutboundDelta(afterRevision uint64) (adapter.ProviderDelta, bool) {
	a.deltaAccess.RLock()
	defer a.deltaAccess.RUnlock()
	if afterRevision == a.deltaRevision {
		return adapter.ProviderDelta{BaseRevision: afterRevision, Revision: afterRevision}, true
	}
	if afterRevision > a.deltaRevision || len(a.deltaHistory) == 0 {
		return adapter.ProviderDelta{}, false
	}
	start := -1
	for index, delta := range a.deltaHistory {
		if delta.BaseRevision == afterRevision {
			start = index
			break
		}
	}
	if start < 0 {
		return adapter.ProviderDelta{}, false
	}
	result := adapter.ProviderDelta{BaseRevision: afterRevision, Revision: afterRevision}
	for index := start; index < len(a.deltaHistory); index++ {
		delta := a.deltaHistory[index]
		if delta.BaseRevision != result.Revision {
			return adapter.ProviderDelta{}, false
		}
		result.Revision = delta.Revision
		result.Upserts = append(result.Upserts, delta.Upserts...)
		result.Removes = append(result.Removes, delta.Removes...)
	}
	// Return owned slices so consumers cannot mutate the bounded history kept
	// by the provider and corrupt a later delta request.
	result.Upserts = slices.Clone(result.Upserts)
	result.Removes = slices.Clone(result.Removes)
	return result, true
}

func (a *Adapter) HealthCheck(ctx context.Context) (map[string]uint16, error) {
	if a.ticker != nil {
		a.ticker.Reset(a.interval)
	}
	return a.healthcheck(ctx)
}

func (a *Adapter) RegisterCallback(callback adapter.ProviderUpdateCallback) *list.Element[adapter.ProviderUpdateCallback] {
	a.callbackAccess.Lock()
	defer a.callbackAccess.Unlock()
	return a.callbacks.PushBack(callback)
}

func (a *Adapter) UnregisterCallback(element *list.Element[adapter.ProviderUpdateCallback]) {
	a.callbackAccess.Lock()
	defer a.callbackAccess.Unlock()
	a.callbacks.Remove(element)
}

func (a *Adapter) UpdateGroups() {
	a.callbackAccess.Lock()
	callbacks := make([]adapter.ProviderUpdateCallback, 0, a.callbacks.Len())
	for element := a.callbacks.Front(); element != nil; element = element.Next() {
		callbacks = append(callbacks, element.Value)
	}
	a.callbackAccess.Unlock()
	for _, callback := range callbacks {
		callback(a.providerTag)
	}
}

func (a *Adapter) Close() error {
	if a.ticker != nil {
		a.ticker.Stop()
	}
	a.deltaAccess.Lock()
	a.deltaHistory = nil
	a.deltaRevision = 0
	a.deltaAccess.Unlock()
	a.outboundsAccess.Lock()
	outbounds := a.outbounds
	endpoints := a.endpoints
	a.outbounds = nil
	a.outboundsByTag = nil
	a.endpoints = nil
	a.endpointsByTag = nil
	a.outboundsAccess.Unlock()
	var err error
	for _, ob := range outbounds {
		if err2 := a.outbound.Remove(ob.Tag()); err2 != nil {
			err = E.Append(err, err2, func(err error) error {
				return E.Cause(err, "close outbound [", ob.Tag(), "]")
			})
		}
	}
	for _, ep := range endpoints {
		if err2 := a.endpoint.Remove(ep.Tag()); err2 != nil {
			err = E.Append(err, err2, func(err error) error {
				return E.Cause(err, "close endpoint [", ep.Tag(), "]")
			})
		}
	}
	return err
}

func (a *Adapter) loopCheck() {
	if !a.paused.Load() {
		a.healthcheck(a.ctx)
	}
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-a.ticker.C:
			if !a.paused.Load() {
				a.healthcheck(a.ctx)
			}
		}
	}
}

func (a *Adapter) SetProviderPaused(paused bool) {
	a.paused.Store(paused)
}

func (a *Adapter) ProviderPaused() bool {
	return a.paused.Load()
}

func (a *Adapter) ProviderConsumers() int {
	a.callbackAccess.Lock()
	defer a.callbackAccess.Unlock()
	return a.callbacks.Len()
}

func (a *Adapter) healthcheck(ctx context.Context) (map[string]uint16, error) {
	result := make(map[string]uint16)
	if ctx == nil {
		ctx = a.ctx
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if a.checking.Swap(true) {
		return result, nil
	}
	defer a.checking.Store(false)
	outbounds := a.Outbounds()
	b, _ := batch.New(ctx, batch.WithConcurrencyNum[any](10))
	var resultAccess sync.Mutex
	checked := make(map[string]bool)
	for _, detour := range outbounds {
		tag := detour.Tag()
		if checked[tag] {
			continue
		}
		checked[tag] = true
		b.Go(tag, func() (any, error) {
			probeCtx, cancel := context.WithTimeout(ctx, a.timeout)
			defer cancel()
			t, err := urltest.URLTest(probeCtx, a.link, detour)
			if err != nil {
				a.logger.Debug("outbound ", tag, " unavailable: ", err)
				a.history.DeleteURLTestHistory(tag)
			} else {
				a.logger.Debug("outbound ", tag, " available: ", t, "ms")
				a.history.StoreURLTestHistory(tag, &adapter.URLTestHistory{
					Time:  time.Now(),
					Delay: t,
				})
				resultAccess.Lock()
				result[tag] = t
				resultAccess.Unlock()
			}
			return nil, nil
		})
	}
	b.Wait()
	return result, nil
}

func (a *Adapter) RewriteDetourForProvider(opts []option.Outbound, endpointOpts ...[]option.Endpoint) {
	tagMapping := make(map[string]string)
	for _, opt := range opts {
		if opt.Tag != "" {
			tagMapping[opt.Tag] = F.ToString(a.providerTag, "/", opt.Tag)
		}
	}
	for _, endpoints := range endpointOpts {
		for _, opt := range endpoints {
			if opt.Tag != "" {
				tagMapping[opt.Tag] = F.ToString(a.providerTag, "/", opt.Tag)
			}
		}
	}
	for _, opt := range opts {
		if dialerWrapper, ok := opt.Options.(option.DialerOptionsWrapper); ok {
			dialerOptions := dialerWrapper.TakeDialerOptions()
			if newDetour, found := tagMapping[dialerOptions.Detour]; found {
				dialerOptions.Detour = newDetour
				dialerWrapper.ReplaceDialerOptions(dialerOptions)
			}
		}
	}
}

func (a *Adapter) RewriteDetourForProviderEndpoints(opts []option.Endpoint, outboundOpts ...[]option.Outbound) {
	tagMapping := make(map[string]string)
	for _, opt := range opts {
		if opt.Tag != "" {
			tagMapping[opt.Tag] = F.ToString(a.providerTag, "/", opt.Tag)
		}
	}
	for _, outbounds := range outboundOpts {
		for _, opt := range outbounds {
			if opt.Tag != "" {
				tagMapping[opt.Tag] = F.ToString(a.providerTag, "/", opt.Tag)
			}
		}
	}
	for _, opt := range opts {
		if dialerWrapper, ok := opt.Options.(option.DialerOptionsWrapper); ok {
			dialerOptions := dialerWrapper.TakeDialerOptions()
			if newDetour, found := tagMapping[dialerOptions.Detour]; found {
				dialerOptions.Detour = newDetour
				dialerWrapper.ReplaceDialerOptions(dialerOptions)
			}
		}
	}
}

func (a *Adapter) resolveEndpointTags(newOpts []option.Endpoint) []string {
	tags := make([]string, len(newOpts))
	seen := make(map[string]bool)
	for i, opt := range newOpts {
		var baseTag string
		if opt.Tag != "" {
			baseTag = F.ToString(a.providerTag, "/", opt.Tag)
		} else {
			baseTag = F.ToString(a.providerTag, "/endpoint-", i)
		}
		identity := providerOptionFingerprint(opt.Type, opt.Tag, opt.Options)
		tag := uniqueProviderTag(baseTag, identity, seen)
		if tag != baseTag {
			a.logger.Warn("duplicate endpoint tag ", baseTag, " in provider, renamed to ", tag)
		}
		seen[tag] = true
		tags[i] = tag
	}
	return tags
}

func (a *Adapter) UpdateEndpoints(oldOpts []option.Endpoint, newOpts []option.Endpoint) {
	newTags := a.resolveEndpointTags(newOpts)
	var (
		oldOptByTag    = make(map[string]option.Endpoint)
		endpoints      []adapter.Outbound
		endpointsByTag = make(map[string]adapter.Outbound)
	)
	for _, opt := range oldOpts {
		oldOptByTag[opt.Tag] = opt
	}
	activeTags := a.activeEndpointTags()
	a.removeUselessEndpoints(newTags)
	for i, opt := range newOpts {
		tag := newTags[i]
		ep, exist := a.endpoint.Get(tag)
		_, active := activeTags[tag]
		previousEndpoint := ep
		if !exist || !active || !reflect.DeepEqual(opt, oldOptByTag[opt.Tag]) {
			err := a.endpoint.Create(
				adapter.WithContext(a.ctx, &adapter.InboundContext{
					Outbound: tag,
				}),
				a.router,
				a.logFactory.NewLogger(F.ToString("endpoint/", opt.Type, "[", tag, "]")),
				tag,
				opt.Type,
				opt.Options,
			)
			if err != nil {
				a.logger.Warn(err, " in ", tag, ", skip create this endpoint")
				if active && previousEndpoint != nil {
					endpoints = append(endpoints, previousEndpoint)
					endpointsByTag[tag] = previousEndpoint
				}
				continue
			}
			ep, _ = a.endpoint.Get(tag)
		}
		if ep == nil {
			a.logger.Warn("endpoint ", tag, " was not registered after create, keeping previous snapshot")
			if active && previousEndpoint != nil {
				endpoints = append(endpoints, previousEndpoint)
				endpointsByTag[tag] = previousEndpoint
			}
			continue
		}
		endpoints = append(endpoints, ep)
		endpointsByTag[tag] = ep
	}
	a.outboundsAccess.Lock()
	a.endpoints = endpoints
	a.endpointsByTag = endpointsByTag
	a.outboundsAccess.Unlock()
	if a.enabled && a.history != nil {
		go a.HealthCheck(a.ctx)
	}
}

func (a *Adapter) removeUselessEndpoints(newTags []string) {
	exists := make(map[string]bool)
	for _, tag := range newTags {
		exists[tag] = true
	}
	a.outboundsAccess.RLock()
	snap := make([]adapter.Outbound, len(a.endpoints))
	copy(snap, a.endpoints)
	a.outboundsAccess.RUnlock()
	for _, ep := range snap {
		tag := ep.Tag()
		if !exists[tag] {
			if err := a.endpoint.Remove(tag); err != nil {
				a.logger.Error(err, "close endpoint [", tag, "]")
			}
		}
	}
}

func (a *Adapter) activeOutboundTags() map[string]bool {
	a.outboundsAccess.RLock()
	defer a.outboundsAccess.RUnlock()
	tags := make(map[string]bool, len(a.outbounds))
	for _, outbound := range a.outbounds {
		tags[outbound.Tag()] = true
	}
	return tags
}

func (a *Adapter) activeEndpointTags() map[string]bool {
	a.outboundsAccess.RLock()
	defer a.outboundsAccess.RUnlock()
	tags := make(map[string]bool, len(a.endpoints))
	for _, endpoint := range a.endpoints {
		tags[endpoint.Tag()] = true
	}
	return tags
}

func (a *Adapter) removeUseless(newTags []string) {
	a.outboundsAccess.RLock()
	if len(a.outbounds) == 0 {
		a.outboundsAccess.RUnlock()
		return
	}
	exists := make(map[string]bool)
	for _, tag := range newTags {
		exists[tag] = true
	}
	snap := make([]adapter.Outbound, len(a.outbounds))
	copy(snap, a.outbounds)
	a.outboundsAccess.RUnlock()
	for _, opt := range snap {
		if !exists[opt.Tag()] {
			if err := a.outbound.Remove(opt.Tag()); err != nil {
				a.logger.Error(err, "close outbound [", opt.Tag(), "]")
			}
		}
	}
}
