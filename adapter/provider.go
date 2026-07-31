package adapter

import (
	"context"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/x/list"
)

type Provider interface {
	Type() string
	Tag() string
	Outbounds() []Outbound
	Outbound(tag string) (Outbound, bool)
	UpdatedAt() time.Time
	HealthCheck(ctx context.Context) (map[string]uint16, error)
	RegisterCallback(callback ProviderUpdateCallback) *list.Element[ProviderUpdateCallback]
	UnregisterCallback(element *list.Element[ProviderUpdateCallback])
}

// ProviderOutboundOptions exposes the structured source options used to build
// provider outbounds. Consumers must treat the returned map as immutable.
type ProviderOutboundOptions interface {
	OutboundOptions() map[string]option.Outbound
}

type ProviderOutboundOptionLookup interface {
	OutboundOption(tag string) (option.Outbound, bool)
}

// ProviderOutboundDelta is an optional append-only change cursor. Consumers
// must fall back to Outbounds when the requested cursor is no longer retained.
// It intentionally exposes tags only; runtime outbound objects stay provider-local.
type ProviderOutboundDelta interface {
	OutboundDeltaRevision() uint64
	OutboundDelta(afterRevision uint64) (ProviderDelta, bool)
}

type ProviderDelta struct {
	BaseRevision uint64
	Revision     uint64
	Upserts      []string
	Removes      []string
}

type ProviderUpdater interface {
	Update() error
}

type ProviderSubscriptionInfo interface {
	SubscriptionInfo() SubscriptionInfo
}

type ProviderRegistry interface {
	option.ProviderOptionsRegistry
	CreateProvider(ctx context.Context, router Router, logFactory log.Factory, tag string, providerType string, options any) (Provider, error)
}

type ProviderManager interface {
	Lifecycle
	Providers() []Provider
	Get(tag string) (Provider, bool)
	Remove(tag string) error
	Create(ctx context.Context, router Router, logFactory log.Factory, tag string, providerType string, options any) error
}

type SubscriptionInfo struct {
	Upload   int64
	Download int64
	Total    int64
	Expire   int64
}

type ProviderUpdateCallback = func(tag string) error
