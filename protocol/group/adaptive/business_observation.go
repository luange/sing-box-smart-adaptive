package adaptive

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var ErrObservationIdentityIncomplete = errors.New("adaptive business observation identity is incomplete")

// businessObservation keeps the runtime identity that actually created a
// connection. It never consults the active catalog to relabel old traffic.
type businessObservation struct {
	pool           *AdaptivePool
	lease          *RuntimeEpochIdentityLease
	guard          ObservationIdentityGuard
	evidence       ObservationEvidence
	service        ServiceContext
	payloadOnce    sync.Once
	failureOnce    sync.Once
	throughputOnce sync.Once
	releaseOnce    sync.Once
}

func (o *businessObservation) observeTLSFailure(delay time.Duration, reason string) {
	if o == nil {
		return
	}
	o.failureOnce.Do(func() {
		permit, allowed := o.pool.health.TryAcquireDomainPermitHandle(o.evidence.Handle, DomainService, "", o.service.ID, time.Now())
		if !allowed {
			o.pool.observationPermitBusy.Add(1)
			return
		}
		evidence := o.evidence
		evidence.Source = SourceTLS
		evidence.Stage = StageServiceApplication
		evidence.Confidence = ConfidenceHigh
		evidence.Outcome = OutcomeFailure
		evidence.Failure = FailureTLS
		evidence.Delay = delay
		evidence.At = time.Now()
		evidence.Reason = reason
		reducer := &HealthObservationReducer{Store: o.pool.health, Settlement: AttemptPermitSettlement{Permit: permit}, BeforeReduce: o.pool.observationReducerHook}
		disposition, publishErr := PublishSettledObservationGuarded(o.pool.sharedObservationIngestor(), o.guard, evidence, reducer)
		o.pool.recordObservationResult(disposition, publishErr)
		if publishErr == nil && disposition == IngestAccepted {
			o.pool.businessTLSFailures.Add(1)
			if snapshot := o.pool.catalog.load(); snapshot != nil {
				if candidate, loaded := snapshot.Candidate(o.evidence.Handle.NodeID); loaded {
					o.pool.switchAudit.RecordFailure(o.service.Session, o.service.ID, candidate, FailureTLS, evidence.At)
				}
			}
			o.pool.leases.Invalidate(o.service.Session, o.evidence.Handle.NodeID)
			o.pool.scheduleFailureProbe(o.evidence.Handle)
			o.pool.persistState()
		}
	})
}

func (p *AdaptivePool) beginBusinessObservation(snapshot *ExecutionSnapshot, candidate Candidate, service ServiceContext) (*businessObservation, error) {
	if snapshot == nil || snapshot.RuntimeEpochID == 0 || snapshot.CatalogRevision == 0 || p.runtimeManager == nil || p.health == nil {
		return nil, ErrObservationIdentityIncomplete
	}
	lease, err := p.runtimeManager.AcquireEpoch(p.groupID, snapshot.RuntimeEpochID)
	if err != nil {
		return nil, err
	}
	evidence := ObservationEvidence{
		RuntimeEpochID: snapshot.RuntimeEpochID, CatalogRevision: snapshot.CatalogRevision, SourceGeneration: snapshot.Generation,
		Handle: candidate.Handle, AttemptID: AttemptID(p.attemptSequence.Add(1)), ServiceID: service.ID, Transport: service.Transport,
	}
	return &businessObservation{pool: p, lease: lease, guard: RuntimeEpochObservationGuard{Lease: lease}, evidence: evidence, service: service}, nil
}

func (o *businessObservation) observePayload(source ObservationSource, delay time.Duration) {
	if o == nil {
		return
	}
	defer func() {
		if recover() != nil {
			o.pool.recordObservationPanic()
		}
	}()
	o.payloadOnce.Do(func() {
		permit, allowed := o.pool.health.TryAcquireDomainPermitHandle(o.evidence.Handle, DomainService, "", o.service.ID, time.Now())
		if !allowed {
			o.pool.observationPermitBusy.Add(1)
			return
		}
		evidence := o.evidence
		evidence.Source = source
		evidence.Stage = StageServiceApplication
		evidence.Confidence = ConfidenceHigh
		evidence.Outcome = OutcomeSuccess
		evidence.Failure = FailureNone
		evidence.Delay = delay
		evidence.At = time.Now()
		reducer := &HealthObservationReducer{Store: o.pool.health, Settlement: AttemptPermitSettlement{Permit: permit}, BeforeReduce: o.pool.observationReducerHook}
		disposition, publishErr := PublishSettledObservationGuarded(o.pool.sharedObservationIngestor(), o.guard, evidence, reducer)
		o.pool.recordObservationResult(disposition, publishErr)
	})
}

func (o *businessObservation) observeThroughput(bytes int64, elapsed time.Duration) {
	if o == nil || bytes < 64*1024 || elapsed < time.Second {
		return
	}
	o.throughputOnce.Do(func() {
		bps := float64(bytes) / elapsed.Seconds()
		if bps <= 0 {
			return
		}
		evidence := o.evidence
		evidence.Source = SourceThroughput
		evidence.Stage = StageServiceApplication
		evidence.Confidence = ConfidenceMedium
		evidence.Outcome = OutcomeSuccess
		evidence.Failure = FailureNone
		evidence.ThroughputBPS = bps
		evidence.At = time.Now()
		reducer := &HealthObservationReducer{Store: o.pool.health, BeforeReduce: o.pool.observationReducerHook}
		disposition, publishErr := PublishSettledObservationGuarded(o.pool.sharedObservationIngestor(), o.guard, evidence, reducer)
		o.pool.recordObservationResult(disposition, publishErr)
	})
}

func (o *businessObservation) release() {
	if o == nil {
		return
	}
	o.releaseOnce.Do(o.lease.Release)
}

func (p *AdaptivePool) wrapBusinessConn(conn net.Conn, snapshot *ExecutionSnapshot, candidate Candidate, service ServiceContext, startedAt time.Time) net.Conn {
	observation, err := p.beginBusinessObservation(snapshot, candidate, service)
	if err != nil {
		p.recordObservationIdentityFailure()
		return conn
	}
	base := &observedConn{Conn: conn, startedAt: startedAt, observation: observation}
	if extended, loaded := conn.(N.ExtendedConn); loaded {
		return &observedExtendedConn{observedConn: base, extended: extended}
	}
	return base
}

type observedConn struct {
	net.Conn
	startedAt   time.Time
	observation *businessObservation
	closeOnce   sync.Once
	closeErr    error
	readBytes   atomic.Int64
	writeBytes  atomic.Int64
	tlsStarted  atomic.Bool
}

func (c *observedConn) observeRead(count int) {
	if count > 0 {
		c.readBytes.Add(int64(count))
		c.observation.observePayload(SourceFirstByte, time.Since(c.startedAt))
	}
}

func (c *observedConn) Read(payload []byte) (int, error) {
	count, err := c.Conn.Read(payload)
	c.observeRead(count)
	if count == 0 && err != nil && c.readBytes.Load() == 0 && c.tlsStarted.Load() && time.Since(c.startedAt) <= 15*time.Second {
		c.observation.observeTLSFailure(time.Since(c.startedAt), errorReason(err))
	}
	if errors.Is(err, io.EOF) {
		c.observeThroughput()
		c.observation.release()
	}
	return count, err
}

func (c *observedConn) Close() error {
	c.closeOnce.Do(func() {
		c.observeThroughput()
		c.closeErr = c.Conn.Close()
		c.observation.release()
	})
	return c.closeErr
}

func (c *observedConn) observeThroughput() {
	c.observation.observeThroughput(c.readBytes.Load()+c.writeBytes.Load(), time.Since(c.startedAt))
}

func (c *observedConn) Write(payload []byte) (int, error) {
	if isTLSClientHello(payload) {
		c.tlsStarted.Store(true)
	}
	count, err := c.Conn.Write(payload)
	if count > 0 {
		c.writeBytes.Add(int64(count))
	}
	return count, err
}

func isTLSClientHello(payload []byte) bool {
	return len(payload) >= 6 && payload[0] == 0x16 && payload[1] == 0x03 && payload[5] == 0x01
}

func (c *observedConn) ReadFrom(reader io.Reader) (int64, error) {
	if readerFrom, loaded := c.Conn.(io.ReaderFrom); loaded {
		count, err := readerFrom.ReadFrom(reader)
		if count > 0 {
			c.writeBytes.Add(count)
		}
		if err == nil || errors.Is(err, io.EOF) {
			c.observeThroughput()
		}
		return count, err
	}
	count, err := io.Copy(c, reader)
	if err == nil || errors.Is(err, io.EOF) {
		c.observeThroughput()
	}
	return count, err
}

func (c *observedConn) WriteTo(writer io.Writer) (int64, error) {
	observedWriter := &payloadObservingWriter{Writer: writer, observe: c.observeRead}
	var count int64
	var err error
	if writerTo, loaded := c.Conn.(io.WriterTo); loaded {
		count, err = writerTo.WriteTo(observedWriter)
	} else {
		count, err = io.Copy(observedWriter, struct{ io.Reader }{c.Conn})
	}
	if err == nil || errors.Is(err, io.EOF) {
		c.observeThroughput()
		c.observation.release()
	}
	return count, err
}

func (c *observedConn) Upstream() any         { return c.Conn }
func (*observedConn) ReaderReplaceable() bool { return false }
func (*observedConn) WriterReplaceable() bool { return false }

type payloadObservingWriter struct {
	io.Writer
	observe func(int)
}

func (w *payloadObservingWriter) Write(payload []byte) (int, error) {
	count, err := w.Writer.Write(payload)
	w.observe(count)
	return count, err
}

type observedExtendedConn struct {
	*observedConn
	extended N.ExtendedConn
}

func (c *observedExtendedConn) ReadBuffer(buffer *buf.Buffer) error {
	before := buffer.Len()
	err := c.extended.ReadBuffer(buffer)
	c.observeRead(buffer.Len() - before)
	if buffer.Len() == before && err != nil && c.readBytes.Load() == 0 && c.tlsStarted.Load() && time.Since(c.startedAt) <= 15*time.Second {
		c.observation.observeTLSFailure(time.Since(c.startedAt), errorReason(err))
	}
	if errors.Is(err, io.EOF) {
		c.observation.release()
	}
	return err
}

func (c *observedExtendedConn) WriteBuffer(buffer *buf.Buffer) error {
	count := buffer.Len()
	if isTLSClientHello(buffer.Bytes()) {
		c.tlsStarted.Store(true)
	}
	err := c.extended.WriteBuffer(buffer)
	if err == nil && count > 0 {
		c.writeBytes.Add(int64(count))
	}
	return err
}

func (p *AdaptivePool) wrapBusinessPacketConn(conn net.PacketConn, snapshot *ExecutionSnapshot, candidate Candidate, service ServiceContext, startedAt time.Time) net.PacketConn {
	observation, err := p.beginBusinessObservation(snapshot, candidate, service)
	if err != nil {
		p.recordObservationIdentityFailure()
		return conn
	}
	base := &observedPacketConn{PacketConn: conn, startedAt: startedAt, observation: observation}
	reader, hasReader := conn.(N.PacketReader)
	writer, hasWriter := conn.(N.PacketWriter)
	switch {
	case hasReader && hasWriter:
		return &observedExtendedPacketConn{observedPacketConn: base, reader: reader, writer: writer}
	case hasReader:
		return &observedPacketReaderConn{observedPacketConn: base, reader: reader}
	case hasWriter:
		return &observedPacketWriterConn{observedPacketConn: base, writer: writer}
	default:
		return base
	}
}

func (p *AdaptivePool) recordObservationResult(disposition IngestDisposition, err error) {
	if p == nil {
		return
	}
	if err != nil {
		p.observationReducerFailure.Add(1)
		p.missedObservations.Add(1)
		return
	}
	switch disposition {
	case IngestAccepted:
	case IngestDuplicate:
		p.observationDuplicate.Add(1)
	case IngestStale:
		p.observationStale.Add(1)
	case IngestBackpressure:
		p.observationBackpressure.Add(1)
		p.missedObservations.Add(1)
	default:
		p.observationReducerFailure.Add(1)
		p.missedObservations.Add(1)
	}
}

func (p *AdaptivePool) recordObservationIdentityFailure() {
	if p == nil {
		return
	}
	p.observationIdentityFailure.Add(1)
	p.missedObservations.Add(1)
}

func (p *AdaptivePool) recordObservationPanic() {
	if p == nil {
		return
	}
	p.observationPanic.Add(1)
	p.missedObservations.Add(1)
}

type observedPacketConn struct {
	net.PacketConn
	startedAt   time.Time
	observation *businessObservation
	closeOnce   sync.Once
	closeErr    error
}

func (c *observedPacketConn) observeRead(count int) {
	if count > 0 {
		c.observation.observePayload(SourceUDP, time.Since(c.startedAt))
	}
}

func (c *observedPacketConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	count, source, err := c.PacketConn.ReadFrom(payload)
	c.observeRead(count)
	return count, source, err
}

func (c *observedPacketConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.PacketConn.Close()
		c.observation.release()
	})
	return c.closeErr
}

func (c *observedPacketConn) Upstream() any         { return c.PacketConn }
func (*observedPacketConn) ReaderReplaceable() bool { return false }
func (*observedPacketConn) WriterReplaceable() bool { return false }

type observedPacketReaderConn struct {
	*observedPacketConn
	reader N.PacketReader
}

func (c *observedPacketReaderConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	before := buffer.Len()
	destination, err := c.reader.ReadPacket(buffer)
	c.observeRead(buffer.Len() - before)
	return destination, err
}

type observedPacketWriterConn struct {
	*observedPacketConn
	writer N.PacketWriter
}

func (c *observedPacketWriterConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	return c.writer.WritePacket(buffer, destination)
}

type observedExtendedPacketConn struct {
	*observedPacketConn
	reader N.PacketReader
	writer N.PacketWriter
}

func (c *observedExtendedPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	before := buffer.Len()
	destination, err := c.reader.ReadPacket(buffer)
	c.observeRead(buffer.Len() - before)
	return destination, err
}

func (c *observedExtendedPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	return c.writer.WritePacket(buffer, destination)
}
