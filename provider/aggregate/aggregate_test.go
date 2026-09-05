package aggregate

import (
	"context"
	"errors"
	"net"
	"regexp"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
)

type fakeOutbound struct{ tag string }

func (f *fakeOutbound) Type() string           { return "fake" }
func (f *fakeOutbound) Tag() string            { return f.tag }
func (f *fakeOutbound) Network() []string      { return []string{N.NetworkTCP} }
func (f *fakeOutbound) Dependencies() []string { return nil }
func (f *fakeOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("not implemented")
}
func (f *fakeOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}

type fakeProvider struct {
	tag       string
	outbounds []adapter.Outbound
	updated   time.Time
}

func (p *fakeProvider) Type() string                  { return "fake" }
func (p *fakeProvider) Tag() string                   { return p.tag }
func (p *fakeProvider) Outbounds() []adapter.Outbound { return p.outbounds }
func (p *fakeProvider) Outbound(tag string) (adapter.Outbound, bool) {
	for _, outbound := range p.outbounds {
		if outbound.Tag() == tag {
			return outbound, true
		}
	}
	return nil, false
}
func (p *fakeProvider) UpdatedAt() time.Time { return p.updated }
func (p *fakeProvider) HealthCheck(context.Context) (map[string]uint16, error) {
	return nil, nil
}
func (p *fakeProvider) RegisterCallback(adapter.ProviderUpdateCallback) *list.Element[adapter.ProviderUpdateCallback] {
	return nil
}
func (p *fakeProvider) UnregisterCallback(*list.Element[adapter.ProviderUpdateCallback]) {}

func TestAggregateMergesChildrenAndAppliesFilter(t *testing.T) {
	keep := &fakeOutbound{tag: "a/keep"}
	filtered := &fakeOutbound{tag: "a/drop"}
	shared := &fakeOutbound{tag: "b/shared"}
	p := &Provider{
		exclude: regexp.MustCompile(`/drop$`),
		children: []adapter.Provider{
			&fakeProvider{tag: "a", outbounds: []adapter.Outbound{keep, filtered}},
			&fakeProvider{tag: "b", outbounds: []adapter.Outbound{shared, keep}},
		},
	}

	p.access.Lock()
	p.rebuildLocked()
	p.access.Unlock()

	got := p.Outbounds()
	if len(got) != 2 {
		t.Fatalf("expected two merged outbounds, got %d", len(got))
	}
	if got[0] != keep || got[1] != shared {
		t.Fatalf("unexpected merge order or object reuse: %#v", got)
	}
	if outbound, ok := p.Outbound("a/keep"); !ok || outbound != keep {
		t.Fatal("aggregate did not index the original child outbound")
	}
}

func TestAggregateOptionsRequireChildren(t *testing.T) {
	if len((option.ProviderAggregateOptions{}).Providers) != 0 {
		t.Fatal("zero-value aggregate options unexpectedly contain children")
	}
}
