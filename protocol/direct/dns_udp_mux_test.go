package direct

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/common/dnsmux"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

func dnsTestMessage(txID uint16, response bool) []byte {
	message := make([]byte, 12)
	binary.BigEndian.PutUint16(message[:2], txID)
	if response {
		message[2] = 0x80
	}
	binary.BigEndian.PutUint16(message[4:6], 1)
	message = append(message, 3, 'w', 'w', 'w', 6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0)
	message = append(message, 0, 1, 0, 1)
	return message
}

func TestDNSMessageKeyMatchesQueryAndResponse(t *testing.T) {
	query := dnsTestMessage(0x1234, false)
	response := dnsTestMessage(0x1234, true)
	require.NotZero(t, dnsmux.MessageKey(query))
	require.Equal(t, dnsmux.MessageKey(query), dnsmux.MessageKey(response))
	response[1]++
	require.NotEqual(t, dnsmux.MessageKey(query), dnsmux.MessageKey(response))
}

func TestDNSMuxSharesLaneAcrossSourcePorts(t *testing.T) {
	first := M.Socksaddr{Addr: netip.MustParseAddr("192.0.2.1"), Port: 10001}
	second := M.Socksaddr{Addr: netip.MustParseAddr("192.0.2.1"), Port: 10002}
	require.Equal(t, dnsmux.AddressLaneKey(first, "if0"), dnsmux.AddressLaneKey(second, "if0"))
}
