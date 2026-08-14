package route

import (
	"errors"
	"testing"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

type completionPacketWriter struct {
	closed error
}

func (w *completionPacketWriter) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	buffer.Release()
	return nil
}

func (w *completionPacketWriter) Close(err error) {
	w.closed = err
}

func TestCloseDNSPacketWriterSignalsAsyncFailure(t *testing.T) {
	writer := new(completionPacketWriter)
	expected := errors.New("dns exchange failed")
	closeDNSPacketWriter(writer, expected)
	if !errors.Is(writer.closed, expected) {
		t.Fatalf("unexpected completion error: %v", writer.closed)
	}
}
