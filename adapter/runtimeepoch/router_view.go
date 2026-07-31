package runtimeepoch

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ adapter.Router = (*RouterView)(nil)

type RouterView struct {
	controller *Controller
	access     sync.Mutex
	trackers   []adapter.ConnectionTracker
}

func NewRouterView(controller *Controller) *RouterView {
	return &RouterView{controller: controller}
}

func (*RouterView) Start(adapter.StartStage) error { return nil }
func (*RouterView) Close() error                   { return nil }

func (v *RouterView) Prepare(router adapter.Router) {
	v.access.Lock()
	trackers := append([]adapter.ConnectionTracker(nil), v.trackers...)
	v.access.Unlock()
	for _, tracker := range trackers {
		router.AppendTracker(tracker)
	}
}

func (v *RouterView) RouteConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	runtime, lease, err := v.controller.Acquire()
	if err != nil {
		return err
	}
	return runtime.Router.RouteConnection(ctx, &leasedConn{Conn: conn, lease: lease}, metadata)
}

func (v *RouterView) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	runtime, lease, err := v.controller.Acquire()
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	runtime.Router.RouteConnectionEx(ctx, conn, metadata, leasedCloseHandler(lease, onClose))
}

func (v *RouterView) RoutePacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	runtime, lease, err := v.controller.Acquire()
	if err != nil {
		return err
	}
	return runtime.Router.RoutePacketConnection(ctx, &leasedPacketConn{PacketConn: conn, lease: lease}, metadata)
}

func (v *RouterView) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	runtime, lease, err := v.controller.Acquire()
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	runtime.Router.RoutePacketConnectionEx(ctx, conn, metadata, leasedCloseHandler(lease, onClose))
}

func leasedCloseHandler(lease adapter.RuntimeEpochLease, upstream N.CloseHandlerFunc) N.CloseHandlerFunc {
	var once sync.Once
	return func(err error) {
		once.Do(func() {
			if upstream != nil {
				upstream(err)
			}
			lease.Release()
		})
	}
}

func (v *RouterView) PreMatch(metadata adapter.InboundContext, firstPacket []byte) adapter.PreMatchResult {
	runtime, lease, err := v.controller.Acquire()
	if err != nil {
		return adapter.PreMatchResult{Action: adapter.PreMatchContinue}
	}
	result := runtime.Router.PreMatch(metadata, firstPacket)
	if result.Action != adapter.PreMatchFlow {
		lease.Release()
		return result
	}
	if _, loaded := result.Outbound.(tun.Port); !loaded {
		lease.Release()
		return result
	}
	factory := &flowTrackerFactory{lease: lease, upstream: result.NewTracker}
	factory.timer = time.AfterFunc(2*time.Second, factory.release)
	result.NewTracker = factory.New
	return result
}

func (v *RouterView) HijackDNSPacket(ctx context.Context, payload []byte, writer N.PacketWriter, metadata adapter.InboundContext) {
	runtime, lease, err := v.controller.Acquire()
	if err != nil {
		return
	}
	runtime.Router.HijackDNSPacket(ctx, payload, newPacketWriter(writer, lease), metadata)
}

func (v *RouterView) AppendTracker(tracker adapter.ConnectionTracker) {
	v.access.Lock()
	v.trackers = append(v.trackers, tracker)
	v.access.Unlock()
	if runtime, lease, err := v.controller.Acquire(); err == nil {
		runtime.Router.AppendTracker(tracker)
		lease.Release()
	}
}

func (v *RouterView) RuleSets() []adapter.RuleSet {
	runtime, lease, err := v.controller.Acquire()
	if err != nil {
		return nil
	}
	defer lease.Release()
	return runtime.Router.RuleSets()
}
func (v *RouterView) RuleSet(tag string) (adapter.RuleSet, bool) {
	runtime, lease, err := v.controller.Acquire()
	if err != nil {
		return nil, false
	}
	defer lease.Release()
	return runtime.Router.RuleSet(tag)
}
func (v *RouterView) Rules() []adapter.Rule {
	runtime, lease, err := v.controller.Acquire()
	if err != nil {
		return nil
	}
	defer lease.Release()
	return runtime.Router.Rules()
}
func (v *RouterView) NeedFindProcess() bool {
	runtime, lease, err := v.controller.Acquire()
	if err != nil {
		return false
	}
	defer lease.Release()
	return runtime.Router.NeedFindProcess()
}
func (v *RouterView) NeedFindNeighbor() bool {
	runtime, lease, err := v.controller.Acquire()
	if err != nil {
		return false
	}
	defer lease.Release()
	return runtime.Router.NeedFindNeighbor()
}
func (v *RouterView) NeighborResolver() adapter.NeighborResolver {
	runtime, lease, err := v.controller.Acquire()
	if err != nil {
		return nil
	}
	defer lease.Release()
	return runtime.Router.NeighborResolver()
}
func (v *RouterView) Rule(uuid string) (adapter.Rule, bool) {
	runtime, lease, err := v.controller.Acquire()
	if err != nil {
		return nil, false
	}
	defer lease.Release()
	return runtime.Router.Rule(uuid)
}
func (v *RouterView) ResetNetwork() {
	runtime, lease, err := v.controller.Acquire()
	if err != nil {
		return
	}
	defer lease.Release()
	runtime.Router.ResetNetwork()
}
func (v *RouterView) DefaultDomainMatchStrategy() C.DomainMatchStrategy {
	runtime, lease, err := v.controller.Acquire()
	if err != nil {
		return C.DomainMatchStrategyAsIS
	}
	defer lease.Release()
	return runtime.Router.DefaultDomainMatchStrategy()
}
func (v *RouterView) Reload() {
	runtime, lease, err := v.controller.Acquire()
	if err != nil {
		return
	}
	defer lease.Release()
	runtime.Router.Reload()
}

type leasedConn struct {
	net.Conn
	lease adapter.RuntimeEpochLease
	once  sync.Once
}

func (c *leasedConn) Close() error { err := c.Conn.Close(); c.once.Do(c.lease.Release); return err }

type leasedPacketConn struct {
	N.PacketConn
	lease adapter.RuntimeEpochLease
	once  sync.Once
}

func (c *leasedPacketConn) Close() error {
	err := c.PacketConn.Close()
	c.once.Do(c.lease.Release)
	return err
}

type packetWriter struct {
	upstream N.PacketWriter
	lease    adapter.RuntimeEpochLease
	once     sync.Once
	timer    *time.Timer
}

func newPacketWriter(upstream N.PacketWriter, lease adapter.RuntimeEpochLease) *packetWriter {
	w := &packetWriter{upstream: upstream, lease: lease}
	w.timer = time.AfterFunc(C.DNSTimeout+time.Second, w.release)
	return w
}
func (w *packetWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer w.release()
	return w.upstream.WritePacket(buffer, destination)
}
func (w *packetWriter) release() { w.once.Do(func() { w.timer.Stop(); w.lease.Release() }) }

type flowTrackerFactory struct {
	lease    adapter.RuntimeEpochLease
	upstream func() tun.FlowTracker
	state    atomic.Uint32
	timer    *time.Timer
}

func (f *flowTrackerFactory) New() tun.FlowTracker {
	if !f.state.CompareAndSwap(0, 1) {
		return nil
	}
	f.timer.Stop()
	var upstream tun.FlowTracker
	if f.upstream != nil {
		upstream = f.upstream()
	}
	return &leasedFlowTracker{FlowTracker: upstream, lease: f.lease}
}
func (f *flowTrackerFactory) release() {
	if f.state.CompareAndSwap(0, 2) {
		f.lease.Release()
	}
}

type leasedFlowTracker struct {
	tun.FlowTracker
	lease adapter.RuntimeEpochLease
	once  sync.Once
}

func (t *leasedFlowTracker) AttachFlow(handle tun.FlowHandle) {
	if t.FlowTracker != nil {
		t.FlowTracker.AttachFlow(handle)
	}
}
func (t *leasedFlowTracker) CountForward(n int) {
	if t.FlowTracker != nil {
		t.FlowTracker.CountForward(n)
	}
}
func (t *leasedFlowTracker) CountReverse(n int) {
	if t.FlowTracker != nil {
		t.FlowTracker.CountReverse(n)
	}
}
func (t *leasedFlowTracker) FlowEstablished() {
	if t.FlowTracker != nil {
		t.FlowTracker.FlowEstablished()
	}
}
func (t *leasedFlowTracker) CloseFlow(reason tun.FlowCloseReason) {
	defer t.once.Do(t.lease.Release)
	if t.FlowTracker != nil {
		t.FlowTracker.CloseFlow(reason)
	}
}
