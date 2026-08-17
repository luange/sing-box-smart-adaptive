//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// Module: M-dns-prefill — docs/ebpf-feature-modules-20260805.md
//
// Weak DNS A/AAAA → TC /32 promote for stable leaf DIRECT only.
// Fail-open; does not block DNS Exchange (work runs async).

type dnsPrefillOptions struct {
	enabled bool
	ttl     time.Duration
}

func dnsPrefillOptionsFrom(opts option.EBPFDNSPrefillOptions) dnsPrefillOptions {
	ttl := time.Duration(opts.TTL)
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	return dnsPrefillOptions{enabled: opts.Enabled, ttl: ttl}
}

// OnDNSAnswer implements adapter.DNSAnswerObserver.
// Hot path: filter + schedule; rule walk / promote off Exchange goroutine.
func (i *Inbound) OnDNSAnswer(domain string, addresses []netip.Addr, fromFakeIP bool) {
	if i == nil || fromFakeIP || len(addresses) == 0 || !i.dnsPrefill.enabled {
		return
	}
	if i.dnsPrefillClosed.Load() {
		return
	}
	// Cheap public-IP filter + dedupe before spawning work.
	addrs := filterPrefillAddresses(addresses)
	if len(addrs) == 0 {
		return
	}
	ttl := i.dnsPrefill.ttl
	tag := i.Tag()
	routeRouter := i.dnsPrefillRouter
	outbounds := i.dnsPrefillOutbounds
	if routeRouter == nil || outbounds == nil {
		return
	}
	// Copy domain for async (caller may reuse buffers — domain is already string).
	go i.dnsPrefillApply(tag, domain, addrs, ttl, routeRouter, outbounds)
}

func (i *Inbound) dnsPrefillApply(
	inboundTag, domain string,
	addrs []netip.Addr,
	ttl time.Duration,
	routeRouter adapter.Router,
	outbounds adapter.OutboundManager,
) {
	if i.dnsPrefillClosed.Load() {
		return
	}
	for _, addr := range addrs {
		if i.dnsPrefillClosed.Load() {
			return
		}
		if !dnsPrefillIsStableDirect(routeRouter, outbounds, inboundTag, domain, addr) {
			continue
		}
		if i.promoteLearnedBypass(addr, ttl) {
			i.dnsPrefillPromotes.Add(1)
			if i.logger != nil {
				i.logger.Info("eBPF dns_prefill promote ", addr.String(), " domain=", domain)
			}
		} else if i.logger != nil {
			i.logger.Debug("eBPF dns_prefill refresh ", addr.String(), " domain=", domain)
		}
	}
}

// wireDNSPrefill caches Router/OutboundManager and registers the observer.
// Call once from Start after backend is up.
func (i *Inbound) wireDNSPrefill() {
	if i == nil || !i.dnsPrefill.enabled {
		return
	}
	routeRouter, ok := i.router.(adapter.Router)
	if !ok || routeRouter == nil {
		i.logger.Warn("eBPF dns_prefill disabled: router does not implement adapter.Router")
		i.dnsPrefill.enabled = false
		return
	}
	outbounds := service.FromContext[adapter.OutboundManager](i.ctx)
	if outbounds == nil {
		i.logger.Warn("eBPF dns_prefill disabled: missing outbound manager")
		i.dnsPrefill.enabled = false
		return
	}
	i.dnsPrefillRouter = routeRouter
	i.dnsPrefillOutbounds = outbounds
	i.dnsPrefillClosed.Store(false)
	service.MustRegister[adapter.DNSAnswerObserver](i.ctx, i)
	i.logger.Info("eBPF dns_prefill enabled ttl=", i.dnsPrefill.ttl)
}

func (i *Inbound) stopDNSPrefill() {
	if i == nil {
		return
	}
	i.dnsPrefillClosed.Store(true)
}

// filterPrefillAddresses drops invalid/private/dupes. Preserves first-seen order.
func filterPrefillAddresses(addresses []netip.Addr) []netip.Addr {
	if len(addresses) == 0 {
		return nil
	}
	out := make([]netip.Addr, 0, len(addresses))
	seen := make(map[netip.Addr]struct{}, len(addresses))
	for _, addr := range addresses {
		if !addr.IsValid() {
			continue
		}
		addr = addr.Unmap()
		if addr.IsUnspecified() || addr.IsLoopback() || addr.IsMulticast() ||
			addr.IsPrivate() || addr.IsLinkLocalUnicast() {
			continue
		}
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	return out
}

// dnsPrefillIsStableDirect: per-IP rule walk (geoip may differ across multi-A).
// Port 0 avoids false negatives from port-only rules; domain set for geosite.
func dnsPrefillIsStableDirect(
	routeRouter adapter.Router,
	outboundManager adapter.OutboundManager,
	inboundTag string,
	domain string,
	addr netip.Addr,
) bool {
	metadata := adapter.InboundContext{
		Inbound:     inboundTag,
		InboundType: C.TypeEBPF,
		Network:     N.NetworkTCP,
		Destination: M.SocksaddrFromNetIP(netip.AddrPortFrom(addr, 0)),
		Domain:      domain,
	}
	if addr.Is4() {
		metadata.IPVersion = 4
	} else {
		metadata.IPVersion = 6
	}

	outboundTag := ""
	for _, rule := range routeRouter.Rules() {
		metadata.ResetRuleCache()
		if !rule.Match(&metadata) {
			continue
		}
		switch action := rule.Action().(type) {
		case *R.RuleActionRoute:
			outboundTag = action.Outbound
		case *R.RuleActionBypass:
			if action.Outbound == "" {
				return true // true kernel bypass
			}
			outboundTag = action.Outbound
		case *R.RuleActionDirect:
			return true
		case *R.RuleActionReject, *R.RuleActionHijackDNS:
			return false
		case *R.RuleActionSniff,
			*R.RuleActionRouteOptions, *R.RuleActionResolve:
			continue // non-terminal
		default:
			return false // fail-closed (unknown / predefined / …)
		}
		break
	}

	var outbound adapter.Outbound
	if outboundTag == "" {
		outbound = outboundManager.Default()
	} else {
		var loaded bool
		outbound, loaded = outboundManager.Outbound(outboundTag)
		if !loaded || outbound == nil {
			return false
		}
	}
	return isStableDirectLeafType(outbound.Type())
}

func isStableDirectLeafType(outboundType string) bool {
	switch outboundType {
	case C.TypeDirect, C.TypeEBPF:
		return true
	default:
		return false
	}
}
