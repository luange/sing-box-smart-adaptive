package runtimeepoch

import (
	"errors"
	"sync"

	"github.com/sagernet/sing-box/adapter"
)

var ErrUnavailable = errors.New("runtime epoch unavailable")

type Runtime struct {
	ID           uint64
	Router       adapter.Router
	DNSRouter    adapter.DNSRouter
	DNSTransport adapter.DNSTransportManager
	Outbound     adapter.OutboundManager
	Provider     adapter.ProviderManager
	Endpoint     adapter.EndpointManager
	Publish      func() error
	Retire       func()
	Close        func() error
}

func (r Runtime) validate() error {
	switch {
	case r.Router == nil:
		return errors.New("runtime epoch has no router")
	case r.DNSRouter == nil:
		return errors.New("runtime epoch has no DNS router")
	case r.DNSTransport == nil:
		return errors.New("runtime epoch has no DNS transport manager")
	case r.Outbound == nil:
		return errors.New("runtime epoch has no outbound manager")
	case r.Provider == nil:
		return errors.New("runtime epoch has no provider manager")
	case r.Endpoint == nil:
		return errors.New("runtime epoch has no endpoint manager")
	case r.Close == nil:
		return errors.New("runtime epoch has no close function")
	default:
		return nil
	}
}

type epoch struct {
	runtime    Runtime
	references int64
	published  bool
	retired    bool
	closing    bool
	done       chan struct{}
}

type Controller struct {
	access   sync.Mutex
	current  *epoch
	all      map[*epoch]struct{}
	nextID   uint64
	closed   bool
	closeErr error
}

func New() *Controller {
	return &Controller{all: make(map[*epoch]struct{})}
}

func (c *Controller) PrepareInitial(runtime Runtime) (uint64, error) {
	if err := runtime.validate(); err != nil {
		return 0, err
	}
	c.access.Lock()
	defer c.access.Unlock()
	if c.closed {
		return 0, ErrUnavailable
	}
	if c.current != nil || len(c.all) != 0 {
		return 0, errors.New("initial runtime epoch already prepared")
	}
	runtime.ID = c.assignID(runtime.ID)
	state := &epoch{runtime: runtime, done: make(chan struct{})}
	c.current = state
	c.all[state] = struct{}{}
	return runtime.ID, nil
}

func (c *Controller) ActivateInitial() (uint64, error) {
	c.access.Lock()
	defer c.access.Unlock()
	if c.closed || c.current == nil || c.current.retired {
		return 0, ErrUnavailable
	}
	if !c.current.published {
		if c.current.runtime.Publish != nil {
			if err := c.current.runtime.Publish(); err != nil {
				return 0, err
			}
		}
		c.current.published = true
	}
	return c.current.runtime.ID, nil
}

func (c *Controller) Publish(runtime Runtime) (uint64, error) {
	if err := runtime.validate(); err != nil {
		return 0, err
	}
	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		return 0, ErrUnavailable
	}
	runtime.ID = c.assignID(runtime.ID)
	if runtime.Publish != nil {
		if err := runtime.Publish(); err != nil {
			c.access.Unlock()
			closeErr := runtime.Close()
			return 0, errors.Join(err, closeErr)
		}
	}
	next := &epoch{runtime: runtime, published: true, done: make(chan struct{})}
	previous := c.current
	c.current = next
	c.all[next] = struct{}{}
	if previous != nil {
		c.retireLocked(previous)
	}
	c.access.Unlock()
	return runtime.ID, nil
}

func (c *Controller) Acquire() (Runtime, adapter.RuntimeEpochLease, error) {
	c.access.Lock()
	state := c.current
	if c.closed || state == nil || state.retired || !state.published {
		c.access.Unlock()
		return Runtime{}, nil, ErrUnavailable
	}
	state.references++
	c.access.Unlock()
	return state.runtime, &lease{controller: c, epoch: state}, nil
}

func (c *Controller) CurrentID() uint64 {
	c.access.Lock()
	defer c.access.Unlock()
	if c.current == nil {
		return 0
	}
	return c.current.runtime.ID
}

func (c *Controller) Close() error {
	c.access.Lock()
	if !c.closed {
		c.closed = true
		c.current = nil
		for state := range c.all {
			c.retireLocked(state)
		}
	}
	wait := make([]<-chan struct{}, 0, len(c.all))
	for state := range c.all {
		wait = append(wait, state.done)
	}
	c.access.Unlock()
	for _, done := range wait {
		<-done
	}
	c.access.Lock()
	err := c.closeErr
	c.access.Unlock()
	return err
}

func (c *Controller) assignID(requested uint64) uint64 {
	if requested > c.nextID {
		c.nextID = requested
		return requested
	}
	c.nextID++
	return c.nextID
}

func (c *Controller) retireLocked(state *epoch) {
	if state.retired {
		return
	}
	state.retired = true
	if state.runtime.Retire != nil {
		state.runtime.Retire()
	}
	c.closeIfIdleLocked(state)
}

func (c *Controller) closeIfIdleLocked(state *epoch) {
	if !state.retired || state.references != 0 || state.closing {
		return
	}
	state.closing = true
	go func() {
		err := state.runtime.Close()
		c.access.Lock()
		c.closeErr = errors.Join(c.closeErr, err)
		delete(c.all, state)
		close(state.done)
		c.access.Unlock()
	}()
}

type lease struct {
	controller *Controller
	epoch      *epoch
	once       sync.Once
}

func (l *lease) Release() {
	l.once.Do(func() {
		l.controller.access.Lock()
		l.epoch.references--
		if l.epoch.references < 0 {
			l.controller.access.Unlock()
			panic("runtime epoch lease released below zero")
		}
		l.controller.closeIfIdleLocked(l.epoch)
		l.controller.access.Unlock()
	})
}
