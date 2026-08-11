package direct

import (
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/common/dnsmux"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

func TestDNSMuxSharesLaneAcrossSourcePorts(t *testing.T) {
	first := M.Socksaddr{Addr: netip.MustParseAddr("192.0.2.1"), Port: 10001}
	second := M.Socksaddr{Addr: netip.MustParseAddr("192.0.2.1"), Port: 10002}
	require.Equal(t, dnsmux.AddressLaneKey(first, "if0"), dnsmux.AddressLaneKey(second, "if0"))
}
