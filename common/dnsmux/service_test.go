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

type testWriter struct{ N.PacketWriter }

type echoDNSHandler struct{}

func (echoDNSHandler) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	for {
		buffer := buf.NewPacket()
		destination, err := conn.ReadPacket(buffer)
		if err != nil {
			buffer.Release()
			return
		}
		buffer.Bytes()[2] |= 0x80
		if err = conn.WritePacket(buffer, destination); err != nil {
			return
		}
	}
}

type countingWriter struct{ replies *atomic.Uint64 }

func (w countingWriter) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	buffer.Release()
	w.replies.Add(1)
	return nil
}

func TestTransactionFIFO(t *testing.T) {
	current := &lane{transactions: make(map[uint64][]transaction), parent: &Service{options: Options{MaxTransactions: 4}}}
	first := &testWriter{}
	second := &testWriter{}
	require.True(t, current.remember(7, transaction{writer: first, createdAt: time.Now()}))
	require.True(t, current.remember(7, transaction{writer: second, createdAt: time.Now()}))
	actual, loaded := current.take(7)
	require.True(t, loaded)
	require.Same(t, first, actual.writer)
	actual, loaded = current.take(7)
	require.True(t, loaded)
	require.Same(t, second, actual.writer)
}

func TestServiceSharesOneLaneAcrossHighCardinalitySourcePorts(t *testing.T) {
	var replies atomic.Uint64
	service := New(Options{
		Handler: echoDNSHandler{},
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
