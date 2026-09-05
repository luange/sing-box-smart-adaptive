// Package aggregate exposes several existing outbound providers as one
// read-only provider view. It never owns or recreates child outbounds.
package aggregate

import (
	"context"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/provider"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
)

func RegisterProvider(registry *provider.Registry) {
	provider.Register[option.ProviderAggregateOptions](registry, C.ProviderTypeAggregate, NewProvider)
}

var _ adapter.Provider = (*Provider)(nil)

type childSubscription struct {
	provider adapter.Provider
	callback *list.Element[adapter.ProviderUpdateCallback]
}

type Provider struct {
	tag     string
	logger  log.ContextLogger
	manager adapter.ProviderManager
	refs    []string
	exclude *regexp.Regexp
	include *regexp.Regexp

	resolveOnce sync.Once
	resolveErr  error
	closed      atomic.Bool
	access      sync.RWMutex
	children    []adapter.Provider
	childSubs   []childSubscription
	outbounds   []adapter.Outbound
	byTag       map[string]adapter.Outbound

	callbackAccess sync.Mutex
	callbacks      list.List[adapter.ProviderUpdateCallback]
}

func NewProvider(ctx context.Context, _ adapter.Router, logFactory log.Factory, tag string, options option.ProviderAggregateOptions) (adapter.Provider, error) {
	if len(options.Providers) == 0 {
		return nil, E.New("aggregate provider requires at least one provider")
	}
	manager := service.FromContext[adapter.ProviderManager](ctx)
	if manager == nil {
		return nil, E.New("missing provider manager")
	}
	return &Provider{
		tag:     tag,
		logger:  logFactory.NewLogger(F.ToString("provider/aggregate[", tag, "]")),
		manager: manager,
		refs:    append([]string(nil), options.Providers...),
		exclude: func() *regexp.Regexp {
			if options.Exclude == nil {
				return nil
			}
			return options.Exclude.Build()
		}(),
		include: func() *regexp.Regexp {
			if options.Include == nil {
				return nil
			}
			return options.Include.Build()
		}(),
	}, nil
}

// StartContext resolves all children after the provider manager has created
// every configured provider. Resolution is order-independent and detects
// aggregate cycles before any callbacks are installed.
func (p *Provider) StartContext(_ context.Context, _ *adapter.HTTPStartContext) error {
	return p.resolveAggregate(nil)
}

func (p *Provider) resolveAggregate(path []string) error {
	for _, tag := range path {
		if tag == p.tag {
			return E.New("aggregate provider cycle: ", strings.Join(append(path, p.tag), " -> "))
		}
	}
	p.resolveOnce.Do(func() {
		p.resolveErr = p.resolveChildren(append(path, p.tag))
	})
	return p.resolveErr
}

func (p *Provider) resolveChildren(path []string) error {
	children := make([]adapter.Provider, 0, len(p.refs))
	seen := make(map[string]struct{}, len(p.refs))
	for _, ref := range p.refs {
		if ref == "" {
			return E.New("aggregate provider ", p.tag, " contains an empty provider reference")
		}
		if _, loaded := seen[ref]; loaded {
			return E.New("aggregate provider ", p.tag, " references provider more than once: ", ref)
		}
		seen[ref] = struct{}{}
		child, loaded := p.manager.Get(ref)
		if !loaded {
			return E.New("aggregate provider ", p.tag, " references missing provider: ", ref)
		}
		if aggregate, ok := child.(*Provider); ok {
			if err := aggregate.resolveAggregate(path); err != nil {
				return err
			}
		}
		children = append(children, child)
	}

	subs := make([]childSubscription, 0, len(children))
	for _, child := range children {
		child := child
		element := child.RegisterCallback(func(_ string) error {
			return p.childUpdated()
		})
		subs = append(subs, childSubscription{provider: child, callback: element})
	}

	p.access.Lock()
	p.children = children
	p.childSubs = subs
	p.rebuildLocked()
	p.access.Unlock()
	return nil
}

func (p *Provider) rebuildLocked() {
	outbounds := make([]adapter.Outbound, 0)
	byTag := make(map[string]adapter.Outbound)
	for _, child := range p.children {
		for _, outbound := range child.Outbounds() {
			if outbound == nil {
				continue
			}
			tag := outbound.Tag()
			if p.exclude != nil && p.exclude.MatchString(tag) {
				continue
			}
			if p.include != nil && !p.include.MatchString(tag) {
				continue
			}
			if _, loaded := byTag[tag]; loaded {
				if p.logger != nil {
					p.logger.Warn("duplicate outbound ", tag, " from aggregate children; keeping first")
				}
				continue
			}
			byTag[tag] = outbound
			outbounds = append(outbounds, outbound)
		}
	}
	p.outbounds = outbounds
	p.byTag = byTag
}

func (p *Provider) childUpdated() error {
	if p.closed.Load() {
		return nil
	}
	p.access.Lock()
	p.rebuildLocked()
	p.access.Unlock()
	p.notifyUpdated()
	return nil
}

func (p *Provider) notifyUpdated() {
	p.callbackAccess.Lock()
	callbacks := make([]adapter.ProviderUpdateCallback, 0, p.callbacks.Len())
	for element := p.callbacks.Front(); element != nil; element = element.Next() {
		callbacks = append(callbacks, element.Value)
	}
	p.callbackAccess.Unlock()
	for _, callback := range callbacks {
		if err := callback(p.tag); err != nil {
			p.logger.Warn("aggregate update callback: ", err)
		}
	}
}

func (p *Provider) Type() string { return C.ProviderTypeAggregate }

func (p *Provider) Tag() string { return p.tag }

func (p *Provider) Outbounds() []adapter.Outbound {
	p.access.RLock()
	defer p.access.RUnlock()
	return append([]adapter.Outbound(nil), p.outbounds...)
}

func (p *Provider) Outbound(tag string) (adapter.Outbound, bool) {
	p.access.RLock()
	defer p.access.RUnlock()
	outbound, loaded := p.byTag[tag]
	return outbound, loaded
}

func (p *Provider) UpdatedAt() time.Time {
	p.access.RLock()
	defer p.access.RUnlock()
	var latest time.Time
	for _, child := range p.children {
		if updated := child.UpdatedAt(); updated.After(latest) {
			latest = updated
		}
	}
	return latest
}

func (p *Provider) HealthCheck(ctx context.Context) (map[string]uint16, error) {
	if err := p.resolveAggregate(nil); err != nil {
		return nil, err
	}
	p.access.RLock()
	children := append([]adapter.Provider(nil), p.children...)
	p.access.RUnlock()
	result := make(map[string]uint16)
	seen := make(map[string]struct{}, len(children))
	var firstErr error
	for _, child := range children {
		if _, loaded := seen[child.Tag()]; loaded {
			continue
		}
		seen[child.Tag()] = struct{}{}
		checked, err := child.HealthCheck(ctx)
		if err != nil && firstErr == nil {
			firstErr = E.Cause(err, "healthcheck provider/", child.Tag())
		}
		for tag, delay := range checked {
			result[tag] = delay
		}
	}
	return result, firstErr
}

func (p *Provider) RegisterCallback(callback adapter.ProviderUpdateCallback) *list.Element[adapter.ProviderUpdateCallback] {
	p.callbackAccess.Lock()
	defer p.callbackAccess.Unlock()
	return p.callbacks.PushBack(callback)
}

func (p *Provider) UnregisterCallback(element *list.Element[adapter.ProviderUpdateCallback]) {
	p.callbackAccess.Lock()
	defer p.callbackAccess.Unlock()
	p.callbacks.Remove(element)
}

// Update refreshes each unique child once. It deliberately does not pause or
// close children because they may also be referenced independently.
func (p *Provider) Update() error {
	if err := p.resolveAggregate(nil); err != nil {
		return err
	}
	p.access.RLock()
	children := append([]adapter.Provider(nil), p.children...)
	p.access.RUnlock()
	seen := make(map[string]struct{}, len(children))
	var firstErr error
	for _, child := range children {
		if _, loaded := seen[child.Tag()]; loaded {
			continue
		}
		seen[child.Tag()] = struct{}{}
		updater, ok := child.(adapter.ProviderUpdater)
		if !ok {
			continue
		}
		if err := updater.Update(); err != nil && firstErr == nil {
			firstErr = E.Cause(err, "update provider/", child.Tag())
		}
	}
	return firstErr
}

func (p *Provider) Close() error {
	if !p.closed.Swap(true) {
		p.access.Lock()
		subs := p.childSubs
		p.childSubs = nil
		p.children = nil
		p.outbounds = nil
		p.byTag = nil
		p.access.Unlock()
		for _, sub := range subs {
			sub.provider.UnregisterCallback(sub.callback)
		}
	}
	return nil
}
