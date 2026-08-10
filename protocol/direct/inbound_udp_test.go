package direct

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/require"
)

func TestDirectUDPNATOptions(t *testing.T) {
	dnsOptions, err := directUDPNATOptions(option.DirectInboundOptions{
		ListenOptions: option.ListenOptions{ListenPort: 53},
	}, 5*time.Second)
	require.NoError(t, err)
	require.Equal(t, uint32(16), dnsOptions.Capacity)
	require.Equal(t, 2, dnsOptions.QueueDepth)

	dataOptions, err := directUDPNATOptions(option.DirectInboundOptions{}, time.Minute)
	require.NoError(t, err)
	require.Equal(t, uint32(1024), dataOptions.Capacity)
	require.Equal(t, 64, dataOptions.QueueDepth)

	customOptions, err := directUDPNATOptions(option.DirectInboundOptions{
		UDPSessionCapacity: 32,
		UDPQueueDepth:      4,
	}, time.Second)
	require.NoError(t, err)
	require.Equal(t, uint32(32), customOptions.Capacity)
	require.Equal(t, 4, customOptions.QueueDepth)

	_, err = directUDPNATOptions(option.DirectInboundOptions{UDPSessionCapacity: 4097}, time.Second)
	require.Error(t, err)
	_, err = directUDPNATOptions(option.DirectInboundOptions{UDPQueueDepth: 257}, time.Second)
	require.Error(t, err)
}
