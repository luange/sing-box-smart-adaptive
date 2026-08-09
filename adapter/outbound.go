package adapter

import (
	"context"
	"net"
	"net/netip"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	N "github.com/sagernet/sing/common/network"
)

// Note: for proxy protocols, outbound creates early connections by default.

type Outbound interface {
	Type() string
	Tag() string
	Network() []string
	Dependencies() []string
	N.Dialer
}

type OutboundWithPreferredRoutes interface {
	Outbound
	PreferredDomain(metadata *InboundContext, domain string) bool
	PreferredAddress(metadata *InboundContext, address netip.Addr) bool
}

type OutboundWithMultiplex interface {
	Outbound
	MultiplexEnabled() bool
}

type FlowOutbound interface {
	Outbound
	tun.Port
	PreMatchFlow(network string, destination netip.Addr) PreMatchAction
}

type FlowOutboundDomainResolver interface {
	FlowOutbound
	FlowDomainResolveOptions() DNSQueryOptions
}

// SpliceCapableConn is an optional extension for eBPF sockmap splice.
// Official protocol leaves need not implement it; direct/socks/http already
// return bare post-handshake TCP that the eBPF layer can use.
type SpliceCapableConn interface {
	// SpliceReady returns underlying TCP after framing is done; nil = not ready.
	SpliceReady() *net.TCPConn
}

// ConnectionSplicer is registered by eBPF inbound when outbound_offload.splice is on.
type ConnectionSplicer interface {
	TrySpliceTCP(
		ctx context.Context,
		inboundType string,
		dialer N.Dialer,
		local net.Conn,
		remote net.Conn,
		metadata InboundContext,
		onClose N.CloseHandlerFunc,
	) bool
}

// VerdictLearner is registered by eBPF inbound when outbound_offload.verdict.mode != off.
type VerdictLearner interface {
	MaybeLearnTCP(ctx context.Context, dialer N.Dialer, metadata InboundContext, remote netip.AddrPort)
	MaybeLearnUDP(ctx context.Context, dialer N.Dialer, metadata InboundContext, remote netip.AddrPort)
}

type OutboundRegistry interface {
	option.OutboundOptionsRegistry
	CreateOutbound(ctx context.Context, router Router, logger log.ContextLogger, tag string, outboundType string, options any) (Outbound, error)
}

type OutboundManager interface {
	Lifecycle
	Outbounds() []Outbound
	Outbound(tag string) (Outbound, bool)
	Default() Outbound
	Remove(tag string) error
	Create(ctx context.Context, router Router, logger log.ContextLogger, tag string, outboundType string, options any) error
}
