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

const dnsPrefillWorkerLimit = 2

func dnsPrefillOptionsFrom(opts option.EBPFDNSPrefillOptions) dnsPrefillOptions {
	ttl := time.Duration(opts.TTL)
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	return dnsPrefillOptions{enabled: opts.Enabled, ttl: ttl}
}

// OnDNSAnswer implements adapter.DNSAnswerObserver.
// Hot path: filter + schedule; rule walk / promote off Exchange goroutine.
//
// Paths:
//   - fromFakeIP: v3 authoritative FakeIP hint (policy_offload.fakeip), no prefill required
//   - real DNS:   dns_prefill promote and/or v3 DNS strong hint when policy_offload.dns_ip_hint
func (i *Inbound) OnDNSAnswer(domain string, addresses []netip.Addr, fromFakeIP bool) {
	if i == nil || len(addresses) == 0 {
		return
	}
	if fromFakeIP {
		if i.dnsPrefillClosed.Load() {
			return
		}
		i.onFakeIPAnswer(addresses)
		return
	}
	// Admit before filtering or allocating. Answers are advisory hints, so a
	// full worker budget is safely fail-open and cannot create one goroutine per
	// DNS response during browser/messenger bursts.
	if !i.acquireDNSPrefillSlot() {
		return
	}
	release := true
	defer func() {
		if release {
			i.releaseDNSPrefillWorker()
		}
	}()
	v3DNS := i.v3DNSHintEnabled()
	if !i.dnsPrefill.enabled && !v3DNS {
		return
	}
	// Cheap public-IP filter + dedupe before spawning work.
	addrs := filterPrefillAddresses(addresses)
	if len(addrs) == 0 {
		return
	}
	ttl := i.dnsPrefill.ttl
	if ttl <= 0 {
		ttl = time.Minute
	}
	tag := i.Tag()
	routeRouter := i.dnsPrefillRouter
	outbounds := i.dnsPrefillOutbounds
	if routeRouter == nil || outbounds == nil {
		// Lazy bind if v3 DNS path started without wireDNSPrefill.
		if rr, ok := i.router.(adapter.Router); ok {
			routeRouter = rr
		}
		outbounds = service.FromContext[adapter.OutboundManager](i.ctx)
	}
	if routeRouter == nil || outbounds == nil {
		return
	}
	release = false
	go func() {
		defer i.releaseDNSPrefillWorker()
		i.dnsPrefillApply(tag, domain, addrs, ttl, routeRouter, outbounds)
	}()
}

func (i *Inbound) acquireDNSPrefillSlot() bool {
	i.dnsPrefillAccess.Lock()
	defer i.dnsPrefillAccess.Unlock()
	if i.dnsPrefillClosed.Load() {
		return false
	}
	if i.dnsPrefillSlots == nil {
		i.dnsPrefillSlots = make(chan struct{}, dnsPrefillWorkerLimit)
	}
	select {
	case i.dnsPrefillSlots <- struct{}{}:
		// Add while holding the admission lock. StopDNSPrefill takes the same
		// lock before Wait, so it cannot observe a zero counter and return while
		// this callback is about to start a worker.
		i.dnsPrefillWorkers.Add(1)
		return true
	default:
		i.dnsPrefillQueueDrops.Add(1)
		return false
	}
}

func (i *Inbound) releaseDNSPrefillWorker() {
	i.dnsPrefillAccess.Lock()
	slots := i.dnsPrefillSlots
	i.dnsPrefillAccess.Unlock()
	if slots != nil {
		<-slots
	}
	i.dnsPrefillWorkers.Done()
}

func (i *Inbound) v3DNSHintEnabled() bool {
	if i == nil || i.sharedNetwork == nil || !i.sharedNetwork.engineV3 {
		return false
	}
	po := i.sharedOptions.PolicyOffload
	if !po.Enabled {
		return false
	}
	switch po.DNSIPHint {
	case "safe", "strong":
		return true
	default:
		return po.FakeIP
	}
}

func (i *Inbound) v3FakeIPEnabled() bool {
	if i == nil || i.sharedNetwork == nil || !i.sharedNetwork.engineV3 {
		return false
	}
	po := i.sharedOptions.PolicyOffload
	return po.Enabled && po.FakeIP
}

// onFakeIPAnswer publishes authoritative FakeIP → kernel DNS hint (design §8.1).
func (i *Inbound) onFakeIPAnswer(addresses []netip.Addr) {
	if !i.v3FakeIPEnabled() || i.sharedNetwork == nil {
		return
	}
	ttl := i.dnsPrefill.ttl
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	for _, addr := range addresses {
		if !addr.IsValid() {
			continue
		}
		addr = addr.Unmap()
		// FakeIP ranges are typically 198.18/15 or similar — do not require public filter.
		i.sharedNetwork.observeV3DNS(addr, true, 1 /* DNSEvidenceFakeIP */, ttl)
	}
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
			// Still record proxy evidence for v3 conflict isolation when hint on.
			if i.v3DNSHintEnabled() && i.sharedNetwork != nil {
				i.sharedNetwork.observeV3DNS(addr, false, 2 /* strong observed but not direct */, ttl)
			}
			continue
		}
		if i.dnsPrefill.enabled {
			if i.promoteLearnedBypass(addr, ttl) {
				i.dnsPrefillPromotes.Add(1)
				if i.logger != nil {
					i.logger.Debug("eBPF dns_prefill promote ", addr.String(), " domain=", domain)
				}
			} else if i.logger != nil {
				i.logger.Debug("eBPF dns_prefill refresh ", addr.String(), " domain=", domain)
			}
		} else if i.v3DNSHintEnabled() && i.sharedNetwork != nil {
			// policy_offload DNS path without legacy dns_prefill module.
			i.sharedNetwork.observeV3DNS(addr, true, 2 /* DNSEvidenceStrong */, ttl)
			if i.sharedNetwork.backend != nil {
				p := netip.PrefixFrom(addr.Unmap(), prefixBits(addr)).Masked()
				if err := i.sharedNetwork.backend.MergeStaticDirect(p); err != nil && i.logger != nil {
					i.logger.Debug("eBPF v3 dns hint merge: ", err)
				}
			}
		}
	}
}

func prefixBits(addr netip.Addr) int {
	if addr.Is4() {
		return 32
	}
	return 128
}

// wireDNSPrefill caches Router/OutboundManager and registers the observer.
// Call once from Start after backend is up.
// Registers for dns_prefill and/or engine=v3 policy_offload DNS/FakeIP hints.
func (i *Inbound) wireDNSPrefill() {
	if i == nil {
		return
	}
	needObserver := i.dnsPrefill.enabled || i.v3DNSHintEnabled() || i.v3FakeIPEnabled()
	if !needObserver {
		return
	}
	routeRouter, ok := i.router.(adapter.Router)
	if !ok || routeRouter == nil {
		if i.dnsPrefill.enabled {
			i.logger.Warn("eBPF dns_prefill disabled: router does not implement adapter.Router")
			i.dnsPrefill.enabled = false
		}
		return
	}
	outbounds := service.FromContext[adapter.OutboundManager](i.ctx)
	if outbounds == nil {
		if i.dnsPrefill.enabled {
			i.logger.Warn("eBPF dns_prefill disabled: missing outbound manager")
			i.dnsPrefill.enabled = false
		}
		return
	}
	i.dnsPrefillRouter = routeRouter
	i.dnsPrefillOutbounds = outbounds
	i.dnsPrefillAccess.Lock()
	if i.dnsPrefillSlots == nil {
		i.dnsPrefillSlots = make(chan struct{}, dnsPrefillWorkerLimit)
	}
	i.dnsPrefillClosed.Store(false)
	i.dnsPrefillAccess.Unlock()
	if hub := service.FromContext[*adapter.DNSAnswerObserverHub](i.ctx); hub != nil {
		hub.Add(i)
	} else {
		// Fallback for tests / partial contexts without hub.
		service.MustRegister[adapter.DNSAnswerObserver](i.ctx, i)
	}
	if i.dnsPrefill.enabled {
		i.logger.Info("eBPF dns_prefill enabled ttl=", i.dnsPrefill.ttl)
	}
	if i.v3DNSHintEnabled() || i.v3FakeIPEnabled() {
		i.logger.Info("eBPF v3 DNS/FakeIP hint observer enabled dns_ip_hint=",
			i.sharedOptions.PolicyOffload.DNSIPHint, " fakeip=", i.sharedOptions.PolicyOffload.FakeIP)
	}
}

func (i *Inbound) stopDNSPrefill() {
	if i == nil {
		return
	}
	i.dnsPrefillAccess.Lock()
	i.dnsPrefillClosed.Store(true)
	i.dnsPrefillAccess.Unlock()
	if hub := service.FromContext[*adapter.DNSAnswerObserverHub](i.ctx); hub != nil {
		hub.Remove(i)
	}
	// No new callbacks can enter after unregistering; wait for admitted work so
	// a restart cannot retain route/outbound references from the old lifecycle.
	i.dnsPrefillWorkers.Wait()
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
