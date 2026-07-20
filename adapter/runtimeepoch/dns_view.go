package runtimeepoch

import (
	"context"
	"net/netip"
	"sync"

	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
)

var _ adapter.DNSRouter = (*DNSView)(nil)

type DNSView struct{ controller *Controller }

func NewDNSView(controller *Controller) *DNSView { return &DNSView{controller: controller} }
func (*DNSView) Start(adapter.StartStage) error  { return nil }
func (*DNSView) Close() error                    { return nil }

func (v *DNSView) Exchange(ctx context.Context, message *dns.Msg, options adapter.DNSQueryOptions) (*dns.Msg, error) {
	runtime, lease, err := v.controller.Acquire()
	if err != nil {
		return nil, err
	}
	defer lease.Release()
	return runtime.DNSRouter.Exchange(ctx, message, options)
}

func (v *DNSView) ExchangeAsync(ctx context.Context, message *dns.Msg, options adapter.DNSQueryOptions, callback func(*dns.Msg, error)) {
	runtime, lease, err := v.controller.Acquire()
	if err != nil {
		if callback != nil {
			callback(nil, err)
		}
		return
	}
	var once sync.Once
	stopCancel := context.AfterFunc(ctx, func() { once.Do(lease.Release) })
	runtime.DNSRouter.ExchangeAsync(ctx, message, options, func(response *dns.Msg, exchangeErr error) {
		stopCancel()
		once.Do(lease.Release)
		if callback != nil {
			callback(response, exchangeErr)
		}
	})
}

func (v *DNSView) Lookup(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	runtime, lease, err := v.controller.Acquire()
	if err != nil {
		return nil, err
	}
	defer lease.Release()
	return runtime.DNSRouter.Lookup(ctx, domain, options)
}
func (v *DNSView) ClearCache() {
	if runtime, lease, err := v.controller.Acquire(); err == nil {
		runtime.DNSRouter.ClearCache()
		lease.Release()
	}
}
func (v *DNSView) LookupReverseMapping(ip netip.Addr) (string, bool) {
	runtime, lease, err := v.controller.Acquire()
	if err != nil {
		return "", false
	}
	defer lease.Release()
	return runtime.DNSRouter.LookupReverseMapping(ip)
}
func (v *DNSView) Rules() []adapter.DNSRule {
	runtime, lease, err := v.controller.Acquire()
	if err != nil {
		return nil
	}
	defer lease.Release()
	return runtime.DNSRouter.Rules()
}
func (v *DNSView) Rule(uuid string) (adapter.DNSRule, bool) {
	runtime, lease, err := v.controller.Acquire()
	if err != nil {
		return nil, false
	}
	defer lease.Release()
	return runtime.DNSRouter.Rule(uuid)
}
func (v *DNSView) ResetNetwork() {
	if runtime, lease, err := v.controller.Acquire(); err == nil {
		runtime.DNSRouter.ResetNetwork()
		lease.Release()
	}
}
