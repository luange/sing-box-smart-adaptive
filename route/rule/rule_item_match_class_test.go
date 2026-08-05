package rule

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/stretchr/testify/require"
)

type classStubItem struct {
	class   adapter.RouteMatchInputs
	matched bool
}

func (s *classStubItem) Match(*adapter.InboundContext) bool { return s.matched }
func (s *classStubItem) String() string                     { return "stub" }
func (s *classStubItem) MatchClass() adapter.RouteMatchInputs {
	return s.class
}

func TestMatchInputsAccumulatesOnRejectedRule(t *testing.T) {
	// Core Q3 assertion: domain rule miss then IP rule hit → Domain|IP both present.
	rule := &abstractDefaultRule{
		items: []RuleItem{
			&classStubItem{class: adapter.RouteMatchDomain, matched: false},
			&classStubItem{class: adapter.RouteMatchIP, matched: true},
		},
	}
	var meta adapter.InboundContext
	ok := rule.matchInner(&meta)
	require.False(t, ok, "first item rejects")
	require.Equal(t, adapter.RouteMatchDomain, meta.MatchInputs&adapter.RouteMatchDomain,
		"rejected domain item must still accumulate Domain")
	// Only first item runs until false — IP not evaluated after domain miss in same rule.
	// Multi-rule path: simulate sequential rules manually.
	var meta2 adapter.InboundContext
	r1 := &abstractDefaultRule{items: []RuleItem{
		&classStubItem{class: adapter.RouteMatchDomain, matched: false},
	}}
	r2 := &abstractDefaultRule{items: []RuleItem{
		&classStubItem{class: adapter.RouteMatchIP, matched: true},
	}}
	_ = r1.matchInner(&meta2)
	_ = r2.matchInner(&meta2)
	require.Equal(t, adapter.RouteMatchDomain|adapter.RouteMatchIP, meta2.MatchInputs,
		"domain miss + later IP hit must accumulate both classes")
}

func TestMatchClassIPPortNetwork(t *testing.T) {
	ip, err := NewIPCIDRItem(false, []string{"1.2.3.0/24"})
	require.NoError(t, err)
	require.Equal(t, adapter.RouteMatchIP, ip.MatchClass())

	port := NewPortItem(false, []uint16{443})
	require.Equal(t, adapter.RouteMatchPort, port.MatchClass())

	netItem := NewNetworkItem([]string{"tcp"})
	require.Equal(t, adapter.RouteMatchNetwork, netItem.MatchClass())
}

func TestMatchClassDomainProcessUser(t *testing.T) {
	dom, err := NewDomainItem([]string{"example.com"}, nil, 0)
	require.NoError(t, err)
	require.Equal(t, adapter.RouteMatchDomain, dom.MatchClass())

	proc := NewProcessItem([]string{"curl"})
	require.Equal(t, adapter.RouteMatchProcess, proc.MatchClass())

	user := NewUserItem([]string{"alice"})
	require.Equal(t, adapter.RouteMatchUser, user.MatchClass())
}

func TestRuleSetItemMatchClassUnstartedUnknown(t *testing.T) {
	item := NewRuleSetItem(nil, []string{"geoip-cn"}, false, false)
	require.Equal(t, adapter.RouteMatchUnknown, item.MatchClass())
}

func TestRuleSetItemMatchClassPureIP(t *testing.T) {
	item := &RuleSetItem{setList: []adapter.RuleSet{
		&fakeRuleSetMeta{meta: adapter.RuleSetMetadata{ContainsIPCIDRRule: true}},
	}}
	require.Equal(t, adapter.RouteMatchIP, item.MatchClass())
}

func TestRuleSetItemMatchClassNonIP(t *testing.T) {
	item := &RuleSetItem{setList: []adapter.RuleSet{
		&fakeRuleSetMeta{meta: adapter.RuleSetMetadata{
			ContainsIPCIDRRule:    true,
			ContainsNonIPCIDRRule: true,
		}},
	}}
	c := item.MatchClass()
	require.NotEqual(t, adapter.RouteMatchInputs(0), c&adapter.RouteMatchDomain)
	require.NotEqual(t, adapter.RouteMatchInputs(0), c&^adapter.RouteMatchIPOnly)
}

type fakeRuleSetMeta struct {
	fakeRuleSet
	meta adapter.RuleSetMetadata
}

func (f *fakeRuleSetMeta) Metadata() adapter.RuleSetMetadata { return f.meta }
