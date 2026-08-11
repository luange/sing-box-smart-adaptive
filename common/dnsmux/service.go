package dnsmux

import (
	"context"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const defaultMaxTransactions = 4096

type PrepareFunc func(source, destination M.Socksaddr, userData any) (context.Context, N.PacketWriter, N.CloseHandlerFunc)

// HandleFunc must consume or unpack payload before returning. A response may be
// written asynchronously through writer; the service keeps only lightweight
// transaction accounting, never a per-client PacketConn or goroutine.
type HandleFunc func(ctx context.Context, payload []byte, writer N.PacketWriter, source, destination M.Socksaddr, userData any)

type Options struct {
	Handle          HandleFunc
	Prepare         PrepareFunc
	Timeout         time.Duration
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

type transaction struct {
	laneKey   string
	onClose   N.CloseHandlerFunc
	createdAt time.Time
}

type lane struct {
	transactions int
	lastActive   time.Time
}

type Service struct {
	options      Options
	access       sync.Mutex
	lanes        map[string]*lane
	transactions map[uint64]transaction
	nextID       atomic.Uint64
	closed       chan struct{}
	once         sync.Once
	queries      atomic.Uint64
	replies      atomic.Uint64
	misses       atomic.Uint64
	rejected     atomic.Uint64
}

func New(options Options) *Service {
	if options.Handle == nil || options.Prepare == nil {
		panic("dnsmux: missing handle or prepare callback")
	}
	if options.Timeout <= 0 {
		options.Timeout = time.Minute
	}
	if options.MaxTransactions <= 0 {
		options.MaxTransactions = defaultMaxTransactions
	}
	service := &Service{
		options:      options,
		lanes:        make(map[string]*lane),
		transactions: make(map[uint64]transaction),
		closed:       make(chan struct{}),
	}
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
	ctx, writer, onClose := s.options.Prepare(source, destination, userData)
	if writer == nil {
		s.rejected.Add(1)
		return false
	}
	key := defaultLaneKey(source)
	if s.options.LaneKey != nil {
		key = s.options.LaneKey(source, userData)
	}
	now := time.Now()
	id := s.nextID.Add(1)
	s.access.Lock()
	if len(s.transactions) >= s.options.MaxTransactions {
		s.access.Unlock()
		if onClose != nil {
			onClose(syscall.ENOBUFS)
		}
		s.rejected.Add(1)
		return false
	}
	current := s.lanes[key]
	if current == nil {
		current = &lane{}
		s.lanes[key] = current
	}
	current.transactions++
	current.lastActive = now
	s.transactions[id] = transaction{laneKey: key, onClose: onClose, createdAt: now}
	s.access.Unlock()

	s.queries.Add(1)
	s.options.Handle(ctx, payload, &trackingWriter{service: s, id: id, writer: writer}, source, destination, userData)
	return true
}

type trackingWriter struct {
	service *Service
	id      uint64
	writer  N.PacketWriter
	once    sync.Once
}

func (w *trackingWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	err := w.writer.WritePacket(buffer, destination)
	w.once.Do(func() { w.service.complete(w.id, err) })
	return err
}

func (s *Service) complete(id uint64, writeErr error) {
	entry, loaded := s.remove(id)
	if !loaded {
		s.misses.Add(1)
		return
	}
	if entry.onClose != nil {
		entry.onClose(writeErr)
	}
	if writeErr == nil {
		s.replies.Add(1)
	}
}

func (s *Service) remove(id uint64) (transaction, bool) {
	s.access.Lock()
	entry, loaded := s.transactions[id]
	if loaded {
		delete(s.transactions, id)
		if current := s.lanes[entry.laneKey]; current != nil {
			current.transactions--
			current.lastActive = time.Now()
		}
	}
	s.access.Unlock()
	return entry, loaded
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
			s.expire(now, false)
		case <-s.closed:
			return
		}
	}
}

func (s *Service) expire(now time.Time, all bool) {
	var expired []transaction
	s.access.Lock()
	for id, entry := range s.transactions {
		if all || now.Sub(entry.createdAt) >= s.options.Timeout {
			delete(s.transactions, id)
			expired = append(expired, entry)
			if current := s.lanes[entry.laneKey]; current != nil {
				current.transactions--
			}
		}
	}
	for key, current := range s.lanes {
		if current.transactions == 0 && (all || now.Sub(current.lastActive) >= s.options.Timeout) {
			delete(s.lanes, key)
		}
	}
	s.access.Unlock()
	for _, entry := range expired {
		if entry.onClose != nil {
			entry.onClose(io.ErrClosedPipe)
		}
	}
}

func (s *Service) Purge() {
	s.expire(time.Now(), true)
}

func (s *Service) Close() {
	s.once.Do(func() { close(s.closed) })
	s.Purge()
}

func (s *Service) RuntimeStats() RuntimeStats {
	s.access.Lock()
	lanes := len(s.lanes)
	transactions := len(s.transactions)
	s.access.Unlock()
	return RuntimeStats{
		Lanes: uint64(lanes), Transactions: uint64(transactions), Queries: s.queries.Load(),
		Replies: s.replies.Load(), TransactionMisses: s.misses.Load(), AdmissionRejected: s.rejected.Load(),
	}
}

func AddressLaneKey(source M.Socksaddr, suffix string) string {
	address := source.Addr.Unmap()
	if !address.IsValid() {
		address = netip.IPv4Unspecified()
	}
	return address.String() + "\x00" + suffix
}

var _ N.PacketWriter = (*trackingWriter)(nil)
