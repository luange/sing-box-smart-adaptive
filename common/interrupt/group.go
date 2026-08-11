package interrupt

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/x/list"
)

type Group struct {
	access      sync.Mutex
	connections list.List[*groupConnItem]
}

type groupConnItem struct {
	conn       io.Closer
	isExternal bool
	isProvider bool
	key        string
	createdAt  time.Time
	lastActive atomic.Int64
	removed    atomic.Bool
}

type InterruptPolicy struct {
	IdleThreshold time.Duration
	LongConnAge   time.Duration
	GracePeriod   time.Duration
	ForceAll      bool
	TargetKey     string
}

type InterruptResult struct {
	Interrupted int
	Idle        int
	Short       int
	Kept        int
	KeptLong    int
}

func NewGroup() *Group {
	return &Group{}
}

func (g *Group) NewConn(conn net.Conn, isExternal, isProvider bool) net.Conn {
	return g.NewConnWithKey(conn, isExternal, isProvider, "")
}

func (g *Group) NewConnWithKey(conn net.Conn, isExternal, isProvider bool, key string) net.Conn {
	g.access.Lock()
	defer g.access.Unlock()
	now := time.Now()
	value := &groupConnItem{conn: conn, isExternal: isExternal, isProvider: isProvider, key: key, createdAt: now}
	value.lastActive.Store(now.UnixNano())
	item := g.connections.PushBack(value)
	return &Conn{Conn: conn, group: g, element: item}
}

func (g *Group) NewPacketConn(conn net.PacketConn, isExternal, isProvider bool) net.PacketConn {
	return g.NewPacketConnWithKey(conn, isExternal, isProvider, "")
}

func (g *Group) NewPacketConnWithKey(conn net.PacketConn, isExternal, isProvider bool, key string) net.PacketConn {
	g.access.Lock()
	defer g.access.Unlock()
	now := time.Now()
	value := &groupConnItem{conn: conn, isExternal: isExternal, isProvider: isProvider, key: key, createdAt: now}
	value.lastActive.Store(now.UnixNano())
	item := g.connections.PushBack(value)
	return &PacketConn{PacketConn: conn, group: g, element: item}
}

func (g *Group) Interrupt(interruptExternalConnections bool) {
	g.access.Lock()
	defer g.access.Unlock()
	var toDelete []*list.Element[*groupConnItem]
	for element := g.connections.Front(); element != nil; element = element.Next() {
		if !element.Value.isProvider && (!element.Value.isExternal || interruptExternalConnections) {
			element.Value.removed.Store(true)
			element.Value.conn.Close()
			toDelete = append(toDelete, element)
		}
	}
	for _, element := range toDelete {
		g.connections.Remove(element)
	}
}

func (g *Group) InterruptSelective(policy InterruptPolicy) InterruptResult {
	if policy.IdleThreshold <= 0 {
		policy.IdleThreshold = 10 * time.Second
	}
	if policy.LongConnAge <= 0 {
		policy.LongConnAge = 30 * time.Second
	}
	now := time.Now()
	g.access.Lock()
	var result InterruptResult
	var immediate []*list.Element[*groupConnItem]
	var delayed []*groupConnItem
	for element := g.connections.Front(); element != nil; {
		next := element.Next()
		item := element.Value
		if item.isProvider || (policy.TargetKey != "" && item.key != policy.TargetKey) {
			result.Kept++
			element = next
			continue
		}
		lastActive := time.Unix(0, item.lastActive.Load())
		idle := now.Sub(lastActive) >= policy.IdleThreshold
		longActive := now.Sub(item.createdAt) >= policy.LongConnAge && !idle
		if !policy.ForceAll && longActive {
			result.Kept++
			result.KeptLong++
			element = next
			continue
		}
		result.Interrupted++
		item.removed.Store(true)
		if idle {
			result.Idle++
		} else {
			result.Short++
		}
		g.connections.Remove(element)
		if !policy.ForceAll && !idle && policy.GracePeriod > 0 {
			delayed = append(delayed, item)
		} else {
			immediate = append(immediate, element)
		}
		element = next
	}
	g.access.Unlock()
	for _, element := range immediate {
		_ = element.Value.conn.Close()
	}
	for _, item := range delayed {
		if conn, loaded := item.conn.(net.Conn); loaded {
			_ = conn.SetDeadline(now.Add(policy.GracePeriod))
		} else if conn, loaded := item.conn.(net.PacketConn); loaded {
			_ = conn.SetDeadline(now.Add(policy.GracePeriod))
		}
		time.AfterFunc(policy.GracePeriod, func() { _ = item.conn.Close() })
	}
	return result
}
