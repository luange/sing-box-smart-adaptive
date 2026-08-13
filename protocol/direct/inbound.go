package direct

import (
	"context"
	"net"
	"os"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/dnsmux"
	"github.com/sagernet/sing-box/common/listener"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/udpnat2"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.DirectInboundOptions](registry, C.TypeDirect, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	ctx                 context.Context
	router              adapter.Router
	logger              log.ContextLogger
	listener            *listener.Listener
	udpNat              *udpnat.Service
	dnsMux              *dnsmux.Service
	overrideOption      int
	overrideDestination M.Socksaddr
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.DirectInboundOptions) (adapter.Inbound, error) {
	options.UDPFragmentDefault = true
	inbound := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeDirect, tag),
		ctx:     ctx,
		router:  router,
		logger:  logger,
	}
	if options.OverrideAddress != "" && options.OverridePort != 0 {
		inbound.overrideOption = 1
		inbound.overrideDestination = M.ParseSocksaddrHostPort(options.OverrideAddress, options.OverridePort)
	} else if options.OverrideAddress != "" {
		inbound.overrideOption = 2
		inbound.overrideDestination = M.ParseSocksaddrHostPort(options.OverrideAddress, options.OverridePort)
	} else if options.OverridePort != 0 {
		inbound.overrideOption = 3
		inbound.overrideDestination = M.Socksaddr{Port: options.OverridePort}
	}
	var udpTimeout time.Duration
	if options.UDPTimeout != 0 {
		udpTimeout = time.Duration(options.UDPTimeout)
	} else {
		udpTimeout = C.UDPTimeout
	}
	udpNATOptions, err := directUDPNATOptions(options, udpTimeout)
	if err != nil {
		return nil, err
	}
	if options.ListenPort == 53 {
		inbound.dnsMux = dnsmux.New(dnsmux.Options{
			Handle:  inbound.handleDNSPacket,
			Timeout: udpTimeout,
			Prepare: func(source, destination M.Socksaddr, userData any) (context.Context, N.PacketWriter, N.CloseHandlerFunc) {
				_, prepareCtx, writer, onClose := inbound.preparePacketConnection(source, destination, userData)
				return prepareCtx, writer, onClose
			},
		})
	} else {
		inbound.udpNat = udpnat.NewWithOptions(inbound, inbound.preparePacketConnection, udpNATOptions)
	}
	inbound.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           options.Network.Build(),
		Listen:            options.ListenOptions,
		ConnectionHandler: inbound,
		PacketHandler:     inbound,
	})
	return inbound, nil
}

func (i *Inbound) handleDNSPacket(ctx context.Context, payload []byte, writer N.PacketWriter, source, destination M.Socksaddr, _ any) {
	metadata := adapter.InboundContext{
		Inbound:     i.Tag(),
		InboundType: i.Type(),
		Network:     N.NetworkUDP,
		Protocol:    C.ProtocolDNS,
		Source:      source,
		Destination: destination,
	}
	//nolint:staticcheck
	metadata.InboundDetour = i.listener.ListenOptions().Detour
	i.router.HijackDNSPacket(ctx, payload, writer, metadata)
}

func directUDPNATOptions(options option.DirectInboundOptions, timeout time.Duration) (udpnat.Options, error) {
	capacity := options.UDPSessionCapacity
	queueDepth := options.UDPQueueDepth
	if capacity == 0 {
		capacity = 1024
	}
	if queueDepth == 0 {
		queueDepth = 64
	}
	if capacity > 4096 {
		return udpnat.Options{}, E.New("udp_session_capacity exceeds 4096")
	}
	if queueDepth < 1 || queueDepth > 256 {
		return udpnat.Options{}, E.New("udp_queue_depth must be between 1 and 256")
	}
	return udpnat.Options{
		Timeout:    timeout,
		Capacity:   capacity,
		QueueDepth: queueDepth,
	}, nil
}

func (i *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	return i.listener.Start()
}

func (i *Inbound) InterfaceUpdated() {
	if i.udpNat != nil {
		i.udpNat.Purge()
	}
	if i.dnsMux != nil {
		i.dnsMux.Purge()
	}
}

func (i *Inbound) Close() error {
	if i.dnsMux != nil {
		i.dnsMux.Close()
	}
	return i.listener.Close()
}

func (i *Inbound) NewPacket(buffer *buf.Buffer, source M.Socksaddr) {
	if i.dnsMux != nil {
		i.dnsMux.NewPacket(buffer.Bytes(), source, i.listener.UDPAddr(), nil)
		return
	}
	i.udpNat.NewPacket([][]byte{buffer.Bytes()}, source, i.listener.UDPAddr(), nil)
}

func (i *Inbound) NewPacketBatch(buffers []*buf.Buffer, sources []M.Socksaddr) {
	if i.dnsMux != nil {
		for index, buffer := range buffers {
			if index < len(sources) {
				i.dnsMux.NewPacket(buffer.Bytes(), sources[index], i.listener.UDPAddr(), nil)
			}
			buffer.Release()
		}
		return
	}
	i.udpNat.NewPacketBatch(buffers, sources, i.listener.UDPAddr(), nil)
}

func (i *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Inbound = i.Tag()
	metadata.InboundType = i.Type()
	destination := metadata.OriginDestination
	switch i.overrideOption {
	case 1:
		destination = i.overrideDestination
	case 2:
		destination.Addr = i.overrideDestination.Addr
	case 3:
		destination.Port = i.overrideDestination.Port
	}
	metadata.Destination = destination
	if i.overrideOption != 0 {
		i.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	}
	i.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (i *Inbound) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	i.logger.InfoContext(ctx, "inbound packet connection from ", source)
	var metadata adapter.InboundContext
	metadata.Inbound = i.Tag()
	metadata.InboundType = i.Type()
	//nolint:staticcheck
	metadata.InboundDetour = i.listener.ListenOptions().Detour
	//nolint:staticcheck
	metadata.Source = source
	destination = i.listener.UDPAddr()
	switch i.overrideOption {
	case 1:
		destination = i.overrideDestination
	case 2:
		destination.Addr = i.overrideDestination.Addr
	case 3:
		destination.Port = i.overrideDestination.Port
	default:
	}
	i.logger.InfoContext(ctx, "inbound packet connection to ", destination)
	metadata.Destination = destination
	if i.overrideOption != 0 {
		conn = bufio.NewDestinationNATPacketConn(bufio.NewNetPacketConn(conn), i.listener.UDPAddr(), destination)
	}
	i.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

func (i *Inbound) preparePacketConnection(source M.Socksaddr, destination M.Socksaddr, userData any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
	return true, log.ContextWithNewID(i.ctx), &directPacketWriter{i.listener.PacketWriter(), source}, nil
}

type directPacketWriter struct {
	writer N.PacketWriter
	source M.Socksaddr
}

func (w *directPacketWriter) WritePacket(buffer *buf.Buffer, addr M.Socksaddr) error {
	return w.writer.WritePacket(buffer, w.source)
}

func (w *directPacketWriter) CreatePacketBatchWriter() (N.PacketBatchWriter, bool) {
	writer, created := bufio.CreatePacketBatchWriter(w.writer)
	if !created {
		return nil, false
	}
	return &directPacketBatchWriter{
		writer: writer,
		source: w.source,
	}, true
}

type directPacketBatchWriter struct {
	writer N.PacketBatchWriter
	source M.Socksaddr
}

func (w *directPacketBatchWriter) WritePacketBatch(buffers []*buf.Buffer, destinations []M.Socksaddr) error {
	if len(buffers) == 0 || len(buffers) != len(destinations) {
		buf.ReleaseMulti(buffers)
		return os.ErrInvalid
	}
	sources := make([]M.Socksaddr, len(destinations))
	for index := range sources {
		sources[index] = w.source
	}
	return w.writer.WritePacketBatch(buffers, sources)
}
