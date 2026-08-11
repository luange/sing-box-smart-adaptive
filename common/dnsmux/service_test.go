package dnsmux

import (
	"context"
	"encoding/binary"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

type countingWriter struct{ replies *atomic.Uint64 }

func (w countingWriter) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	buffer.Release()
	w.replies.Add(1)
	return nil
}

func TestServiceSharesOneLaneAcrossHighCardinalitySourcePorts(t *testing.T) {
	var replies atomic.Uint64
	service := New(Options{
		Handle: func(_ context.Context, payload []byte, writer N.PacketWriter, _, destination M.Socksaddr, _ any) {
			response := buf.NewSize(len(payload))
			response.Write(payload)
			response.Bytes()[2] |= 0x80
			require.NoError(t, writer.WritePacket(response, destination))
		},
		Timeout: time.Minute,
		Prepare: func(M.Socksaddr, M.Socksaddr, any) (context.Context, N.PacketWriter, N.CloseHandlerFunc) {
			return context.Background(), countingWriter{replies: &replies}, nil
		},
	})
	defer service.Close()
	destination := M.Socksaddr{Addr: netip.MustParseAddr("192.0.2.53"), Port: 53}
	for index := range 100 {
		message := make([]byte, 12)
		binary.BigEndian.PutUint16(message[:2], uint16(index+1))
		binary.BigEndian.PutUint16(message[4:6], 1)
		message = append(message, 1, 'a', 0, 0, 1, 0, 1)
		source := M.Socksaddr{Addr: netip.MustParseAddr("192.0.2.1"), Port: uint16(10000 + index)}
		require.True(t, service.NewPacket(message, source, destination, nil))
	}
	require.Eventually(t, func() bool { return replies.Load() == 100 }, time.Second, 10*time.Millisecond)
	stats := service.RuntimeStats()
	require.Equal(t, uint64(1), stats.Lanes)
	require.Equal(t, uint64(0), stats.Transactions)
	require.Equal(t, uint64(0), stats.TransactionMisses)
}

func TestServiceBoundsOutstandingTransactions(t *testing.T) {
	service := New(Options{
		Handle: func(context.Context, []byte, N.PacketWriter, M.Socksaddr, M.Socksaddr, any) {},
		Prepare: func(M.Socksaddr, M.Socksaddr, any) (context.Context, N.PacketWriter, N.CloseHandlerFunc) {
			return context.Background(), countingWriter{replies: new(atomic.Uint64)}, nil
		},
		Timeout: time.Minute, MaxTransactions: 2,
	})
	defer service.Close()
	message := make([]byte, 12)
	source := M.Socksaddr{Addr: netip.MustParseAddr("192.0.2.1"), Port: 10000}
	destination := M.Socksaddr{Addr: netip.MustParseAddr("192.0.2.53"), Port: 53}
	require.True(t, service.NewPacket(message, source, destination, nil))
	require.True(t, service.NewPacket(message, source, destination, nil))
	require.False(t, service.NewPacket(message, source, destination, nil))
	stats := service.RuntimeStats()
	require.Equal(t, uint64(2), stats.Transactions)
	require.Equal(t, uint64(1), stats.AdmissionRejected)
}
