package dnsmux

import (
	"context"
	"encoding/binary"
	"hash/fnv"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	defaultLaneQueue       = 256
	defaultMaxTransactions = 4096
)

type PrepareFunc func(source, destination M.Socksaddr, userData any) (context.Context, N.PacketWriter, N.CloseHandlerFunc)

type Options struct {
	Handler         N.UDPConnectionHandlerEx
	Prepare         PrepareFunc
	Timeout         time.Duration
	LaneQueue       int
	MaxTransactions int
	LaneKey         func(source M.Socksaddr, userData any) string
}

type RuntimeStats struct {
	Lanes             uint64
	Transactions      uint64
	Queries           uint64
	Replies           uint64
	TransactionMisses uint64
	AdmissionRejected uint64
	QueueDrops        uint64
}

type Service struct {
	options    Options
	access     sync.Mutex
	lanes      map[string]*lane
	closed     chan struct{}
	once       sync.Once
	queries    atomic.Uint64
	replies    atomic.Uint64
	misses     atomic.Uint64
	rejected   atomic.Uint64
	queueDrops atomic.Uint64
}

type packet struct {
	buffer      *buf.Buffer
	destination M.Socksaddr
}

type transaction struct {
	writer    N.PacketWriter
	onClose   N.CloseHandlerFunc
	createdAt time.Time
}

type lane struct {
	parent       *Service
	source       M.Socksaddr
	packets      chan packet
	done         chan struct{}
	closeOnce    sync.Once
	access       sync.Mutex
	transactions map[uint64][]transaction
	transactionN int
	lastActive   atomic.Int64
}

func New(options Options) *Service {
	if options.Handler == nil || options.Prepare == nil {
		panic("dnsmux: missing handler or prepare callback")
	}
	if options.Timeout <= 0 {
		options.Timeout = time.Minute
	}
	if options.LaneQueue <= 0 {
		options.LaneQueue = defaultLaneQueue
	}
	if options.MaxTransactions <= 0 {
		options.MaxTransactions = defaultMaxTransactions
	}
	service := &Service{options: options, lanes: make(map[string]*lane), closed: make(chan struct{})}
	go service.reapLoop()
	return service
}

func defaultLaneKey(source M.Socksaddr) string {
	return source.Addr.Unmap().String()
}

func (s *Service) NewPacket(payload []byte, source, destination M.Socksaddr, userData any) bool {
	if len(payload) < 12 {
		s.rejected.Add(1)
		return false
	}
	key := defaultLaneKey(source)
	if s.options.LaneKey != nil {
		key = s.options.LaneKey(source, userData)
	}
	ctx, writer, onClose := s.options.Prepare(source, destination, userData)
	if writer == nil {
		s.rejected.Add(1)
		return false
	}
	s.access.Lock()
	current := s.lanes[key]
	if current != nil {
		select {
		case <-current.done:
			delete(s.lanes, key)
			current = nil
		default:
		}
	}
	if current == nil {
		current = &lane{
			parent: s, source: source, packets: make(chan packet, s.options.LaneQueue), done: make(chan struct{}),
			transactions: make(map[uint64][]transaction),
		}
		current.lastActive.Store(time.Now().UnixNano())
		s.lanes[key] = current
		go s.options.Handler.NewPacketConnectionEx(ctx, current, source, destination, nil)
	}
	s.access.Unlock()

	transactionKey := MessageKey(payload)
	if transactionKey == 0 || !current.remember(transactionKey, transaction{writer: writer, onClose: onClose, createdAt: time.Now()}) {
		if onClose != nil {
			onClose(syscall.ENOBUFS)
		}
		s.rejected.Add(1)
		return false
	}
	packetBuffer := buf.NewSize(len(payload))
	packetBuffer.Write(payload)
	queued := packet{buffer: packetBuffer, destination: destination}
	select {
	case current.packets <- queued:
		current.lastActive.Store(time.Now().UnixNano())
		s.queries.Add(1)
		return true
	case <-current.done:
		packetBuffer.Release()
		current.forget(transactionKey, writer, io.ErrClosedPipe)
		s.queueDrops.Add(1)
		return false
	default:
		packetBuffer.Release()
		current.forget(transactionKey, writer, syscall.ENOBUFS)
		s.queueDrops.Add(1)
		return false
	}
}

func (s *Service) reapLoop() {
	interval := min(s.options.Timeout/2, 30*time.Second)
	if interval < time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			var expired []*lane
			s.access.Lock()
			for key, current := range s.lanes {
				current.prune(now)
				if now.Sub(time.Unix(0, current.lastActive.Load())) >= s.options.Timeout {
					delete(s.lanes, key)
					expired = append(expired, current)
				}
			}
			s.access.Unlock()
			for _, current := range expired {
				_ = current.Close()
			}
		case <-s.closed:
			return
		}
	}
}

func (s *Service) Purge() {
	s.access.Lock()
	lanes := make([]*lane, 0, len(s.lanes))
	for key, current := range s.lanes {
		lanes = append(lanes, current)
		delete(s.lanes, key)
	}
	s.access.Unlock()
	for _, current := range lanes {
		_ = current.Close()
	}
}

func (s *Service) Close() {
	s.once.Do(func() { close(s.closed) })
	s.Purge()
}

func (s *Service) RuntimeStats() RuntimeStats {
	s.access.Lock()
	lanes := uint64(len(s.lanes))
	var transactions uint64
	for _, current := range s.lanes {
		current.access.Lock()
		transactions += uint64(current.transactionN)
		current.access.Unlock()
	}
	s.access.Unlock()
	return RuntimeStats{
		Lanes: lanes, Transactions: transactions, Queries: s.queries.Load(), Replies: s.replies.Load(),
		TransactionMisses: s.misses.Load(), AdmissionRejected: s.rejected.Load(), QueueDrops: s.queueDrops.Load(),
	}
}

func (l *lane) remember(key uint64, value transaction) bool {
	l.access.Lock()
	defer l.access.Unlock()
	if l.transactionN >= l.parent.options.MaxTransactions {
		return false
	}
	l.transactions[key] = append(l.transactions[key], value)
	l.transactionN++
	return true
}

func (l *lane) forget(key uint64, writer N.PacketWriter, closeErr error) {
	l.access.Lock()
	entries := l.transactions[key]
	for index, entry := range entries {
		if entry.writer == writer {
			entries = append(entries[:index], entries[index+1:]...)
			l.transactionN--
			if len(entries) == 0 {
				delete(l.transactions, key)
			} else {
				l.transactions[key] = entries
			}
			l.access.Unlock()
			if entry.onClose != nil {
				entry.onClose(closeErr)
			}
			return
		}
	}
	l.access.Unlock()
}

func (l *lane) take(key uint64) (transaction, bool) {
	l.access.Lock()
	defer l.access.Unlock()
	entries := l.transactions[key]
	if len(entries) == 0 {
		return transaction{}, false
	}
	entry := entries[0]
	if len(entries) == 1 {
		delete(l.transactions, key)
	} else {
		l.transactions[key] = entries[1:]
	}
	l.transactionN--
	return entry, true
}

func (l *lane) prune(now time.Time) {
	var expired []transaction
	l.access.Lock()
	for key, entries := range l.transactions {
		kept := entries[:0]
		for _, entry := range entries {
			if now.Sub(entry.createdAt) < l.parent.options.Timeout {
				kept = append(kept, entry)
			} else {
				expired = append(expired, entry)
				l.transactionN--
			}
		}
		if len(kept) == 0 {
			delete(l.transactions, key)
		} else {
			l.transactions[key] = kept
		}
	}
	l.access.Unlock()
	for _, entry := range expired {
		if entry.onClose != nil {
			entry.onClose(os.ErrDeadlineExceeded)
		}
	}
}

func (l *lane) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	select {
	case incoming := <-l.packets:
		_, err := buffer.ReadOnceFrom(incoming.buffer)
		incoming.buffer.Release()
		return incoming.destination, err
	case <-l.done:
		return M.Socksaddr{}, io.ErrClosedPipe
	}
}

func (l *lane) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	key := MessageKey(buffer.Bytes())
	entry, loaded := l.take(key)
	if !loaded {
		buffer.Release()
		l.parent.misses.Add(1)
		return os.ErrNotExist
	}
	l.lastActive.Store(time.Now().UnixNano())
	err := entry.writer.WritePacket(buffer, destination)
	if entry.onClose != nil {
		entry.onClose(err)
	}
	if err == nil {
		l.parent.replies.Add(1)
	}
	return err
}

func (l *lane) Close() error {
	l.closeOnce.Do(func() {
		close(l.done)
		for {
			select {
			case incoming := <-l.packets:
				incoming.buffer.Release()
			default:
				l.prune(time.Now().Add(2 * l.parent.options.Timeout))
				return
			}
		}
	})
	return nil
}

func (l *lane) LocalAddr() net.Addr              { return l.source }
func (l *lane) SetDeadline(time.Time) error      { return os.ErrInvalid }
func (l *lane) SetReadDeadline(time.Time) error  { return os.ErrInvalid }
func (l *lane) SetWriteDeadline(time.Time) error { return os.ErrInvalid }

func MessageKey(message []byte) uint64 {
	if len(message) < 12 {
		return 0
	}
	txID := binary.BigEndian.Uint16(message[:2])
	questions := binary.BigEndian.Uint16(message[4:6])
	if questions == 0 {
		return uint64(txID)<<32 | 1
	}
	offset := 12
	for labels := 0; labels < 128; labels++ {
		if offset >= len(message) {
			return uint64(txID)<<32 | 1
		}
		length := int(message[offset])
		offset++
		if length == 0 {
			break
		}
		if length&0xc0 == 0xc0 {
			if offset >= len(message) {
				return uint64(txID)<<32 | 1
			}
			offset++
			break
		}
		if length > 63 || offset+length > len(message) {
			return uint64(txID)<<32 | 1
		}
		offset += length
	}
	if offset+4 > len(message) {
		return uint64(txID)<<32 | 1
	}
	offset += 4
	hash := fnv.New32a()
	_, _ = hash.Write(message[12:offset])
	return uint64(txID)<<32 | uint64(hash.Sum32())
}

func AddressLaneKey(source M.Socksaddr, suffix string) string {
	address := source.Addr.Unmap()
	if !address.IsValid() {
		address = netip.IPv4Unspecified()
	}
	return address.String() + "\x00" + suffix
}

var _ N.PacketConn = (*lane)(nil)
