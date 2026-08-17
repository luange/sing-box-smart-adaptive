//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sagernet/netlink"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dnsmux"
	ECommon "github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/redir"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	udpnat "github.com/sagernet/sing/common/udpnat2"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

const (
	sharedNetworkRefresh               = 3 * time.Second
	sharedNetworkDataPlaneToken        = "token"
	sharedNetworkDataPlaneSocketAssign = "socket_assign"
	sharedNetworkRoutingMarkDefault    = 0x53420001
	sharedNetworkRoutingTableDefault   = 2026
	// Default TC priority: run before Android tethering offload (IPv6 prio 2, IPv4 prio 3).
	// Lower value runs earlier. Override via shared_network.tc_priority.
	sharedNetworkTCPriorityDefault = 1
	sharedIngressFilterHandle      = 0x5342
	sharedEgressFilterHandle       = 0x5343
)

type sharedNetwork struct {
	parent             *Inbound
	interfaces         []string
	tcPriority         uint16
	dropUDP443         bool
	dataPlane          string
	flowVerdict        bool
	transparentAccess  sync.Mutex
	transparentWriters map[netip.AddrPort]*transparentWriterEntry
	routingMark        uint32
	routingTable       uint32
	backend            *ECommon.SharedNetworkBackend
	policyRoute        *sharedNetworkPolicyRoute
	tc                 *sharedTCManager
	tcp4               *listener.Listener
	tcp6               *listener.Listener
	udp4               *listener.Listener
	udp6               *listener.Listener
	udpNat             *udpnat.Service
	dnsMux             *dnsmux.Service
	udpClients         udpClientTable
	udpWarnings        udpWarningLimiters
	listenPort         uint16
	closeAccess        sync.Mutex
}

type sharedNetworkIngressInterfaceKey struct{}

func sharedNetworkIngressInterface(ifIndex uint32) string {
	if ifIndex == 0 {
		return ""
	}
	device, err := net.InterfaceByIndex(int(ifIndex))
	if err != nil {
		return ""
	}
	return device.Name
}

func normalizeSharedNetworkOptions(options option.EBPFSharedNetworkOptions) (option.EBPFSharedNetworkOptions, error) {
	if !options.Enabled {
		return option.EBPFSharedNetworkOptions{}, nil
	}
	switch options.DataPlane {
	case "":
		// socket_assign is the safe default: it preserves the original tuple
		// and avoids the per-flow token/session state retained by compatibility
		// mode. Set data_plane="token" explicitly only for legacy deployments.
		options.DataPlane = sharedNetworkDataPlaneSocketAssign
	case sharedNetworkDataPlaneToken:
	case sharedNetworkDataPlaneSocketAssign:
	default:
		return option.EBPFSharedNetworkOptions{}, E.New("unknown shared_network.data_plane: ", options.DataPlane)
	}
	if options.DataPlane == sharedNetworkDataPlaneToken && (options.RoutingMark != 0 || options.RoutingTable != 0) {
		return option.EBPFSharedNetworkOptions{}, E.New("shared_network routing_mark/routing_table require data_plane=socket_assign")
	}
	if options.FlowVerdict && options.DataPlane != sharedNetworkDataPlaneSocketAssign {
		return option.EBPFSharedNetworkOptions{}, E.New("shared_network.flow_verdict requires data_plane=socket_assign")
	}
	if options.DataPlane == sharedNetworkDataPlaneSocketAssign {
		if options.RoutingMark == 0 {
			options.RoutingMark = sharedNetworkRoutingMarkDefault
		}
		if options.RoutingTable == 0 {
			options.RoutingTable = sharedNetworkRoutingTableDefault
		}
		if options.RoutingTable > 0xffffffff {
			return option.EBPFSharedNetworkOptions{}, E.New("invalid shared_network.routing_table")
		}
	}
	if len(options.IncludeInterface) == 0 {
		return option.EBPFSharedNetworkOptions{}, E.New("shared_network.include_interface must not be empty")
	}
	seen := make(map[string]struct{}, len(options.IncludeInterface))
	interfaces := make(badoption.Listable[string], 0, len(options.IncludeInterface))
	for _, interfaceName := range options.IncludeInterface {
		interfaceName = strings.TrimSpace(interfaceName)
		if interfaceName == "" {
			return option.EBPFSharedNetworkOptions{}, E.New("shared_network.include_interface contains an empty interface name")
		}
		if interfaceName == "lo" {
			return option.EBPFSharedNetworkOptions{}, E.New("shared_network.include_interface must not contain lo")
		}
		if _, loaded := seen[interfaceName]; loaded {
			continue
		}
		seen[interfaceName] = struct{}{}
		interfaces = append(interfaces, interfaceName)
	}
	options.IncludeInterface = interfaces
	return options, nil
}

func validateSharedNetworkProtocols(options option.EBPFSharedNetworkOptions, enableUDP bool, dnsMode string) error {
	if options.Enabled && dnsMode == dnsModeHijack && !enableUDP {
		return E.New("shared_network with dns_mode hijack requires UDP")
	}
	return nil
}

func sharedNetworkDropUDP443(options option.EBPFSharedNetworkOptions) bool {
	if options.DropUDP443 == nil {
		return false
	}
	return *options.DropUDP443
}

func sharedNetworkResolveTCPriority(options option.EBPFSharedNetworkOptions) uint16 {
	if options.TCPriority == 0 {
		return sharedNetworkTCPriorityDefault
	}
	return options.TCPriority
}

func newSharedNetwork(parent *Inbound, options option.EBPFSharedNetworkOptions) *sharedNetwork {
	shared := &sharedNetwork{
		parent:       parent,
		interfaces:   append([]string(nil), options.IncludeInterface...),
		tcPriority:   sharedNetworkResolveTCPriority(options),
		dropUDP443:   sharedNetworkDropUDP443(options),
		dataPlane:    options.DataPlane,
		flowVerdict:  options.FlowVerdict,
		routingMark:  options.RoutingMark,
		routingTable: options.RoutingTable,
	}
	udpTimeout := C.UDPTimeout
	if parent.listenOptions.UDPTimeout != 0 {
		udpTimeout = time.Duration(parent.listenOptions.UDPTimeout)
	}
	shared.udpNat = udpnat.New(shared, shared.preparePacketConnection, udpTimeout, false)
	shared.dnsMux = dnsmux.New(dnsmux.Options{
		Handle:  shared.handleDNSPacket,
		Timeout: min(udpTimeout, C.DNSTimeout),
		LaneKey: func(source M.Socksaddr, userData any) string {
			var suffix string
			if ifIndex, loaded := userData.(uint32); loaded {
				suffix = strconv.FormatUint(uint64(ifIndex), 10)
			}
			return dnsmux.AddressLaneKey(source, suffix)
		},
		Prepare: func(source, destination M.Socksaddr, userData any) (context.Context, N.PacketWriter, N.CloseHandlerFunc) {
			ok, prepareCtx, writer, onClose := shared.preparePacketConnection(source, destination, userData)
			if !ok {
				return prepareCtx, nil, onClose
			}
			return prepareCtx, writer, onClose
		},
	})
	return shared
}

func (s *sharedNetwork) handleDNSPacket(ctx context.Context, payload []byte, writer N.PacketWriter, source, destination M.Socksaddr, _ any) {
	metadata := adapter.InboundContext{
		Inbound:     s.parent.Tag(),
		InboundType: s.parent.Type(),
		Network:     N.NetworkUDP,
		Protocol:    C.ProtocolDNS,
		Source:      source,
		Destination: destination,
	}
	if interfaceName, loaded := ctx.Value(sharedNetworkIngressInterfaceKey{}).(string); loaded {
		metadata.InboundInterface = interfaceName
	}
	//nolint:staticcheck
	metadata.InboundDetour = s.parent.listenOptions.Detour
	s.parent.router.HijackDNSPacket(ctx, payload, writer, metadata)
}

func (s *sharedNetwork) Start(parentBackend *ECommon.Backend) error {
	if err := s.startListeners(); err != nil {
		return E.Errors(err, s.closeListeners())
	}
	backend, err := ECommon.PrepareSharedNetwork(
		parentBackend,
		s.listenPort,
		s.parent.enableTCP,
		s.parent.enableUDP,
		s.parent.redirectIPv4,
		s.parent.redirectIPv6,
		s.dropUDP443,
		s.dataPlane == sharedNetworkDataPlaneSocketAssign,
		s.routingMark,
	)
	if err != nil {
		return E.Errors(err, s.closeListeners())
	}
	s.backend = backend
	if err = backend.SetFlowDirect(s.flowVerdict); err != nil {
		return E.Errors(E.Cause(err, "configure shared-network flow verdict"), s.Close())
	}
	if s.dataPlane == sharedNetworkDataPlaneSocketAssign {
		if err = s.registerListenerSockets(); err != nil {
			return E.Errors(E.Cause(err, "register shared-network transparent listeners"), s.Close())
		}
		s.policyRoute, err = installSharedNetworkPolicyRoute(
			s.routingMark,
			s.routingTable,
			s.parent.redirectIPv4.IsValid(),
			s.parent.redirectIPv6.IsValid(),
		)
		if err != nil {
			return E.Errors(err, s.Close())
		}
	}
	s.tc = &sharedTCManager{
		backend:      backend,
		logger:       s.parent.logger,
		interfaces:   s.interfaces,
		priority:     s.tcPriority,
		enableIPv4:   s.parent.redirectIPv4.IsValid(),
		attachEgress: s.dataPlane != sharedNetworkDataPlaneSocketAssign,
		attachments:  make(map[string]*sharedTCAttachment),
	}
	if err = s.tc.Start(); err != nil {
		return E.Errors(err, s.Close())
	}
	programs := "tc/ingress,tc/egress"
	if s.dataPlane == sharedNetworkDataPlaneSocketAssign {
		programs = "tc/ingress+socket-assign"
	}
	s.parent.logger.Info(
		"eBPF shared-network ready: interfaces=[", s.tc.InterfaceString(),
		"], listen_port=", s.listenPort,
		", dns_mode=", s.parent.dnsMode,
		", tc_priority=", s.tcPriority,
		", drop_udp_443=", s.dropUDP443,
		", data_plane=", s.dataPlane,
		", programs=[", programs, "]",
	)
	return nil
}

func (s *sharedNetwork) startListeners() error {
	type listenerSpec struct {
		network string
		ipv6    bool
		target  **listener.Listener
	}
	var specs []listenerSpec
	if s.parent.redirectIPv4.IsValid() {
		if s.parent.enableTCP {
			specs = append(specs, listenerSpec{N.NetworkTCP, false, &s.tcp4})
		}
		if s.parent.enableUDP {
			specs = append(specs, listenerSpec{N.NetworkUDP, false, &s.udp4})
		}
	}
	if s.parent.redirectIPv6.IsValid() {
		if s.parent.enableTCP {
			specs = append(specs, listenerSpec{N.NetworkTCP, true, &s.tcp6})
		}
		if s.parent.enableUDP {
			specs = append(specs, listenerSpec{N.NetworkUDP, true, &s.udp6})
		}
	}
	for _, spec := range specs {
		current := s.newListener(spec.network, spec.ipv6, s.listenPort)
		*spec.target = current
		if err := current.Start(); err != nil {
			return err
		}
		if s.listenPort == 0 {
			var address net.Addr
			if spec.network == N.NetworkTCP {
				address = current.TCPListener().Addr()
			} else {
				address = current.UDPConn().LocalAddr()
			}
			s.listenPort = M.SocksaddrFromNet(address).Port
			if s.listenPort == 0 {
				return E.New("shared-network listener selected an invalid port")
			}
		}
	}
	if s.listenPort == 0 {
		return E.New("shared-network has no enabled listener")
	}
	return nil
}

func (s *sharedNetwork) newListener(network string, ipv6Listener bool, port uint16) *listener.Listener {
	listenOptions := s.parent.listenOptions
	listenAddress := netip.IPv4Unspecified()
	if ipv6Listener {
		listenAddress = netip.IPv6Unspecified()
	}
	listenOptions.Listen = common.Ptr(badoption.Addr(listenAddress))
	listenOptions.ListenPort = port
	listenOptions.BindInterface = ""
	socketAssign := s.dataPlane == sharedNetworkDataPlaneSocketAssign
	return listener.New(listener.Options{
		Context:             s.parent.ctx,
		Logger:              s.parent.logger,
		Network:             []string{network},
		Listen:              listenOptions,
		ConnectionHandler:   s,
		OOBPacketHandler:    s,
		DisablePacketOutput: true,
		TProxy:              socketAssign,
		// E5: MPTCP forced off only for socket_assign (SOCKMAP/sk_assign).
		ForceNoMPTCP:  socketAssign,
		SocketControl: s.parent.socketControl(ipv6Listener),
	})
}

func (s *sharedNetwork) registerListenerSockets() error {
	type registration struct {
		key      uint32
		listener syscall.Conn
	}
	var registrations []registration
	if s.tcp4 != nil {
		conn, ok := s.tcp4.TCPListener().(syscall.Conn)
		if !ok {
			return E.New("IPv4 TCP listener does not expose syscall connection")
		}
		registrations = append(registrations, registration{0, conn})
	}
	if s.udp4 != nil {
		registrations = append(registrations, registration{1, s.udp4.UDPConn()})
	}
	if s.tcp6 != nil {
		conn, ok := s.tcp6.TCPListener().(syscall.Conn)
		if !ok {
			return E.New("IPv6 TCP listener does not expose syscall connection")
		}
		registrations = append(registrations, registration{2, conn})
	}
	if s.udp6 != nil {
		registrations = append(registrations, registration{3, s.udp6.UDPConn()})
	}
	for _, registration := range registrations {
		raw, err := registration.listener.SyscallConn()
		if err != nil {
			return err
		}
		var registerErr error
		if err = raw.Control(func(fd uintptr) {
			registerErr = s.backend.RegisterListenerSocket(registration.key, int(fd))
		}); err != nil {
			return err
		}
		if registerErr != nil {
			return registerErr
		}
	}
	return nil
}

func (s *sharedNetwork) InterfaceUpdated() {
	s.udpNat.Purge()
	s.dnsMux.Purge()
	if s.flowVerdict && s.backend != nil {
		if err := s.backend.InvalidateFlowDirect(); err != nil {
			s.parent.logger.Debug("invalidate shared-network direct flow verdicts: ", err)
		}
	}
	if s.tc != nil {
		s.tc.Wake()
	}
}

func (s *sharedNetwork) Close() error {
	if s == nil {
		return nil
	}
	s.closeAccess.Lock()
	defer s.closeAccess.Unlock()
	s.udpNat.Purge()
	s.dnsMux.Close()
	s.closeTransparentWriters()
	if s.tc != nil {
		if err := s.tc.Close(); err != nil {
			return err
		}
		s.tc = nil
	}
	var routeErr error
	if s.policyRoute != nil {
		routeErr = s.policyRoute.Close()
		if routeErr == nil {
			s.policyRoute = nil
		}
	}
	var backendErr error
	if s.backend != nil {
		backendErr = s.backend.Close()
		if s.backend.IsClosed() {
			s.backend = nil
		}
	}
	return E.Errors(routeErr, backendErr, s.closeListeners())
}

func (s *sharedNetwork) closeListeners() error {
	listeners := []*listener.Listener{s.tcp4, s.tcp6, s.udp4, s.udp6}
	s.tcp4 = nil
	s.tcp6 = nil
	s.udp4 = nil
	s.udp6 = nil
	var closeErr error
	for _, current := range listeners {
		if current == nil {
			continue
		}
		closeErr = E.Errors(closeErr, common.Close(current))
	}
	return closeErr
}

func (s *sharedNetwork) IsClosed() bool {
	if s == nil {
		return true
	}
	s.closeAccess.Lock()
	defer s.closeAccess.Unlock()
	return s.tc == nil && s.policyRoute == nil && s.backend == nil &&
		s.tcp4 == nil && s.tcp6 == nil && s.udp4 == nil && s.udp6 == nil
}

func (s *sharedNetwork) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if s.backend == nil {
		conn.Close()
		return
	}
	client := M.SocksaddrFromNet(conn.RemoteAddr()).AddrPort()
	redirect := M.SocksaddrFromNet(conn.LocalAddr()).AddrPort()
	original, err := s.backend.TakeOriginal(ECommon.ProtocolTCP, client, redirect)
	if err != nil {
		s.parent.logger.ErrorContext(ctx, "lookup shared-network TCP original destination: ", err)
		conn.Close()
		return
	}
	metadata.Inbound = s.parent.Tag()
	metadata.InboundType = s.parent.Type()
	metadata.InboundInterface = sharedNetworkIngressInterface(original.IngressIfIndex)
	metadata.Source = M.SocksaddrFromNetIP(client)
	metadata.Destination = M.SocksaddrFromNetIP(original.Destination)
	s.parent.logger.InfoContext(ctx, "shared-network inbound connection to ", metadata.Destination)
	s.parent.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (s *sharedNetwork) NewPacket(buffer *buf.Buffer, oob []byte, source M.Socksaddr) {
	if s.backend == nil {
		return
	}
	client := source.AddrPort()
	var redirect netip.AddrPort
	if s.dataPlane == sharedNetworkDataPlaneSocketAssign {
		var err error
		redirect, err = redir.GetOriginalDestinationFromOOB(oob)
		if err != nil {
			s.udpWarnings.packetInfo.warnError(s.parent.logger, "read shared-network UDP original destination: ", err)
			return
		}
	} else {
		redirectAddress, err := redirectAddressFromOOB(oob)
		if err != nil {
			s.udpWarnings.packetInfo.warnError(s.parent.logger, "read shared-network UDP token address: ", err)
			return
		}
		redirect = netip.AddrPortFrom(redirectAddress, s.listenPort)
	}
	original, err := s.backend.LookupOriginal(ECommon.ProtocolUDP, client, redirect)
	if err != nil {
		s.udpWarnings.originalDestination.warnError(s.parent.logger, "lookup shared-network UDP original destination: ", err)
		return
	}
	released := s.udpClients.setBinding(client, original.Destination, redirect.Addr(), false)
	s.deleteUDPRedirects(client, released)
	if original.Destination.Port() == 53 {
		s.dnsMux.NewPacket(buffer.Bytes(), source, M.SocksaddrFromNetIP(original.Destination), original.IngressIfIndex)
		return
	}
	s.udpNat.NewPacket([][]byte{buffer.Bytes()}, source, M.SocksaddrFromNetIP(original.Destination), original.IngressIfIndex)
}

func (s *sharedNetwork) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	metadata := adapter.InboundContext{
		Inbound:     s.parent.Tag(),
		InboundType: s.parent.Type(),
		Source:      source,
		Destination: destination,
	}
	if interfaceName, loaded := ctx.Value(sharedNetworkIngressInterfaceKey{}).(string); loaded {
		metadata.InboundInterface = interfaceName
	}
	//nolint:staticcheck
	metadata.InboundDetour = s.parent.listenOptions.Detour
	// Packet connections include short-lived DNS/QUIC flows and can be created
	// thousands of times per second on a gateway.  Logging every flow at info
	// level causes allocation pressure and can grow the log by hundreds of MiB.
	// Keep the diagnostic available without enabling it in normal operation.
	s.parent.logger.DebugContext(ctx, "shared-network inbound packet connection to ", destination)
	s.parent.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

func (s *sharedNetwork) preparePacketConnection(source M.Socksaddr, destination M.Socksaddr, userData any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
	ctx := log.ContextWithNewID(s.parent.ctx)
	if ifIndex, loaded := userData.(uint32); loaded {
		ctx = context.WithValue(ctx, sharedNetworkIngressInterfaceKey{}, sharedNetworkIngressInterface(ifIndex))
	}
	client := source.AddrPort()
	if s.dataPlane == sharedNetworkDataPlaneSocketAssign {
		writer := &sharedPacketWriter{shared: s, client: client}
		return true, ctx, writer, func(error) { writer.closeTransparent() }
	}
	clientState := s.udpClients.retain(client)
	writer := &sharedPacketWriter{
		shared:      s,
		client:      client,
		clientState: clientState,
	}
	return true, ctx, writer, func(error) {
		common.Close(common.PtrOrNil(writer.conn))
		s.deleteUDPRedirects(client, s.udpClients.delete(client, clientState))
	}
}

func (s *sharedNetwork) deleteUDPRedirects(client netip.AddrPort, redirects []netip.Addr) {
	if s.backend == nil || s.dataPlane == sharedNetworkDataPlaneSocketAssign {
		return
	}
	for _, address := range redirects {
		redirect := netip.AddrPortFrom(address, s.listenPort)
		if err := s.backend.DeleteRedirect(ECommon.ProtocolUDP, client, redirect); err != nil {
			s.udpWarnings.cleanup.warnValueError(s.parent.logger, "delete shared-network UDP redirect mapping for ", redirect, ": ", err)
		}
	}
}

type sharedPacketWriter struct {
	shared      *sharedNetwork
	client      netip.AddrPort
	clientState *udpClientState
	conn        *net.UDPConn
	bound       M.Socksaddr
	transparent *transparentWriterEntry
}

type transparentWriterEntry struct {
	conn transparentPacketConn
	refs int
}

type transparentPacketConn interface {
	WriteToUDPAddrPort(buffer []byte, destination netip.AddrPort) (int, error)
	Close() error
}

func (w *sharedPacketWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	if w.shared.dataPlane == sharedNetworkDataPlaneSocketAssign {
		return w.writeTransparent(buffer, destination)
	}
	redirectAddress, loaded := w.clientState.redirectAddress(destination.AddrPort())
	if !loaded {
		return E.New("missing shared-network UDP token for ", destination)
	}
	var udpConn *net.UDPConn
	var controlMessage []byte
	if redirectAddress.Is4() {
		if w.shared.udp4 == nil {
			return E.New("shared-network IPv4 UDP listener is unavailable")
		}
		udpConn = w.shared.udp4.UDPConn()
		controlMessage = (&ipv4.ControlMessage{Src: net.IP(redirectAddress.AsSlice())}).Marshal()
	} else {
		if w.shared.udp6 == nil {
			return E.New("shared-network IPv6 UDP listener is unavailable")
		}
		udpConn = w.shared.udp6.UDPConn()
		controlMessage = (&ipv6.ControlMessage{Src: net.IP(redirectAddress.AsSlice())}).Marshal()
	}
	_, _, err := udpConn.WriteMsgUDPAddrPort(buffer.Bytes(), controlMessage, w.client)
	return err
}

func (w *sharedPacketWriter) writeTransparent(buffer *buf.Buffer, destination M.Socksaddr) error {
	if w.transparent == nil || w.bound != destination {
		w.closeTransparent()
		entry, err := w.shared.retainTransparentWriter(destination)
		if err != nil {
			return err
		}
		w.transparent = entry
		w.bound = destination
	}
	udpConn := w.transparent.conn
	_, err := udpConn.WriteToUDPAddrPort(buffer.Bytes(), w.client)
	if err != nil && isTransparentSocketFatal(err) {
		// Only tear down the shared socket when the descriptor itself is no
		// longer usable.  Per-packet/transient failures such as ENOBUFS must not
		// invalidate the socket for every client sharing this source address.
		w.shared.invalidateTransparentWriter(destination.AddrPort(), w.transparent)
		w.transparent = nil
		w.bound = M.Socksaddr{}
	}
	return err
}

func isTransparentSocketFatal(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, unix.EBADF) || errors.Is(err, unix.ENOTSOCK)
}

func (s *sharedNetwork) retainTransparentWriter(destination M.Socksaddr) (*transparentWriterEntry, error) {
	key := destination.AddrPort()
	s.transparentAccess.Lock()
	defer s.transparentAccess.Unlock()
	if current := s.transparentWriters[key]; current != nil {
		current.refs++
		return current, nil
	}
	current := s.udp4
	if destination.Addr.Is6() {
		current = s.udp6
	}
	if current == nil {
		return nil, E.New("shared-network transparent UDP listener is unavailable")
	}
	var listenConfig net.ListenConfig
	listenConfig.Control = control.Append(listenConfig.Control, control.ReuseAddr())
	listenConfig.Control = control.Append(listenConfig.Control, redir.TProxyWriteBack())
	packetConn, err := current.ListenPacket(listenConfig, s.parent.ctx, "udp", destination.String())
	if err != nil {
		return nil, err
	}
	entry := &transparentWriterEntry{conn: packetConn.(*net.UDPConn), refs: 1}
	if s.transparentWriters == nil {
		s.transparentWriters = make(map[netip.AddrPort]*transparentWriterEntry)
	}
	s.transparentWriters[key] = entry
	return entry, nil
}

func (w *sharedPacketWriter) closeTransparent() {
	if w.transparent == nil {
		return
	}
	w.shared.releaseTransparentWriter(w.bound.AddrPort(), w.transparent)
	w.transparent = nil
	w.bound = M.Socksaddr{}
}

func (s *sharedNetwork) releaseTransparentWriter(key netip.AddrPort, writer *transparentWriterEntry) {
	s.transparentAccess.Lock()
	if s.transparentWriters[key] == writer {
		writer.refs--
		if writer.refs == 0 {
			delete(s.transparentWriters, key)
			_ = writer.conn.Close()
		}
	}
	s.transparentAccess.Unlock()
}

func (s *sharedNetwork) invalidateTransparentWriter(key netip.AddrPort, writer *transparentWriterEntry) {
	s.transparentAccess.Lock()
	if s.transparentWriters[key] == writer {
		delete(s.transparentWriters, key)
		_ = writer.conn.Close()
	}
	s.transparentAccess.Unlock()
}

func (s *sharedNetwork) closeTransparentWriters() {
	s.transparentAccess.Lock()
	for key, writer := range s.transparentWriters {
		_ = writer.conn.Close()
		delete(s.transparentWriters, key)
	}
	s.transparentAccess.Unlock()
}

type sharedTCManager struct {
	backend      *ECommon.SharedNetworkBackend
	logger       interfaceLogger
	interfaces   []string
	priority     uint16
	enableIPv4   bool
	attachEgress bool
	access       sync.Mutex
	attachments  map[string]*sharedTCAttachment
	enabled      bool
	cancel       context.CancelFunc
	done         chan struct{}
	wake         chan struct{}
}

type interfaceLogger interface {
	Info(args ...any)
	Warn(args ...any)
}

type sharedTCAttachment struct {
	interfaceName        string
	ifindex              int
	ingress              *netlink.BpfFilter
	egress               *netlink.BpfFilter
	restoreRouteLocalnet bool
}

func (m *sharedTCManager) Start() error {
	if err := m.reconcile(); err != nil {
		return E.Errors(err, m.closeAttachments())
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.done = make(chan struct{})
	m.wake = make(chan struct{}, 1)
	go m.loop(ctx)
	return nil
}

func (m *sharedTCManager) loop(ctx context.Context) {
	defer close(m.done)
	ticker := time.NewTicker(sharedNetworkRefresh)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-m.wake:
		}
		if err := m.reconcile(); err != nil {
			m.logger.Warn("refresh eBPF shared-network interfaces: ", err)
		}
	}
}

func (m *sharedTCManager) Wake() {
	if m == nil || m.wake == nil {
		return
	}
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

func (m *sharedTCManager) reconcile() error {
	hostAddresses, err := sharedHostAddresses()
	if err != nil {
		return err
	}
	if err = m.backend.UpdateHostAddresses(hostAddresses); err != nil {
		return err
	}
	desired := make(map[string]netlink.Link, len(m.interfaces))
	for _, interfaceName := range m.interfaces {
		link, linkErr := netlink.LinkByName(interfaceName)
		if isSharedNetworkLinkNotFound(linkErr) {
			continue
		}
		if linkErr != nil {
			return E.Cause(linkErr, "find shared-network interface ", interfaceName)
		}
		if linkErr = validateSharedNetworkLink(link); linkErr != nil {
			return linkErr
		}
		desired[interfaceName] = link
	}
	m.access.Lock()
	defer m.access.Unlock()
	for interfaceName, attachment := range m.attachments {
		link, loaded := desired[interfaceName]
		if loaded && link.Attrs().Index == attachment.ifindex {
			continue
		}
		if err = m.detachLocked(attachment); err != nil {
			return E.Cause(err, "detach stale shared-network interface ", interfaceName)
		}
		if err = m.backend.DeleteInterfaceMAC(uint32(attachment.ifindex)); err != nil {
			return E.Cause(err, "delete stale shared-network interface MAC ", interfaceName)
		}
		delete(m.attachments, interfaceName)
		m.logger.Info("eBPF shared-network detached from ", interfaceName)
	}
	for interfaceName, link := range desired {
		if _, loaded := m.attachments[interfaceName]; loaded {
			continue
		}
		if err = m.backend.UpdateInterfaceMAC(uint32(link.Attrs().Index), link.Attrs().HardwareAddr); err != nil {
			return E.Cause(err, "register shared-network interface MAC ", interfaceName)
		}
		attachment, attachErr := attachSharedTC(link, m.backend, m.enableIPv4, m.attachEgress, m.priority)
		if attachErr != nil {
			_ = m.backend.DeleteInterfaceMAC(uint32(link.Attrs().Index))
			return E.Cause(attachErr, "attach eBPF shared-network to ", interfaceName)
		}
		m.attachments[interfaceName] = attachment
		m.logger.Info("eBPF shared-network attached to ", interfaceName, " (ifindex=", link.Attrs().Index, ")")
	}
	return m.updateEnabledLocked(len(m.attachments) > 0)
}

func isSharedNetworkLinkNotFound(err error) bool {
	if errors.Is(err, unix.ENODEV) || errors.Is(err, unix.ENOENT) {
		return true
	}
	var linkNotFoundError netlink.LinkNotFoundError
	return errors.As(err, &linkNotFoundError)
}

func validateSharedNetworkLink(link netlink.Link) error {
	if link == nil || link.Attrs() == nil {
		return E.New("invalid shared-network interface")
	}
	if len(link.Attrs().HardwareAddr) != 6 {
		return E.New("shared-network interface ", link.Attrs().Name, " is not Ethernet-like")
	}
	return nil
}

func (m *sharedTCManager) updateEnabledLocked(enabled bool) error {
	if m.enabled == enabled {
		return nil
	}
	var err error
	if enabled {
		err = m.backend.Enable()
	} else {
		err = m.backend.Disable()
	}
	if err == nil {
		m.enabled = enabled
	}
	return err
}

func (m *sharedTCManager) detachLocked(attachment *sharedTCAttachment) error {
	detachErr := E.Errors(
		detachSharedTCFilter(attachment.ingress),
		detachSharedTCFilter(attachment.egress),
	)
	if detachErr != nil {
		return detachErr
	}
	if attachment.restoreRouteLocalnet {
		return restoreSharedRouteLocalnet(attachment.interfaceName)
	}
	return nil
}

func (m *sharedTCManager) InterfaceString() string {
	m.access.Lock()
	defer m.access.Unlock()
	names := make([]string, 0, len(m.attachments))
	for name := range m.attachments {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return "waiting for " + strings.Join(m.interfaces, ", ")
	}
	return strings.Join(names, ", ")
}

func (m *sharedTCManager) Close() error {
	if m == nil {
		return nil
	}
	if m.cancel != nil {
		m.cancel()
		<-m.done
		m.cancel = nil
	}
	return m.closeAttachments()
}

func (m *sharedTCManager) closeAttachments() error {
	m.access.Lock()
	defer m.access.Unlock()
	var closeErr error
	if err := m.updateEnabledLocked(false); err != nil {
		closeErr = err
	}
	for name, attachment := range m.attachments {
		if err := m.detachLocked(attachment); err != nil {
			closeErr = E.Errors(closeErr, E.Cause(err, "detach shared-network interface ", name))
			continue
		}
		if err := m.backend.DeleteInterfaceMAC(uint32(attachment.ifindex)); err != nil {
			closeErr = E.Errors(closeErr, E.Cause(err, "delete shared-network interface MAC ", name))
		}
		delete(m.attachments, name)
	}
	return closeErr
}

func attachSharedTC(link netlink.Link, backend *ECommon.SharedNetworkBackend, enableIPv4 bool, attachEgress bool, priority uint16) (*sharedTCAttachment, error) {
	if priority == 0 {
		priority = sharedNetworkTCPriorityDefault
	}
	restoreRouteLocalnet := false
	if enableIPv4 && attachEgress {
		var err error
		restoreRouteLocalnet, err = enableSharedRouteLocalnet(link.Attrs().Name)
		if err != nil {
			return nil, err
		}
	}
	if err := ensureClsact(link); err != nil {
		if restoreRouteLocalnet {
			_ = restoreSharedRouteLocalnet(link.Attrs().Name)
		}
		return nil, err
	}
	var egress *netlink.BpfFilter
	var err error
	if attachEgress {
		egress, err = attachSharedTCFilter(
			link,
			netlink.HANDLE_MIN_EGRESS,
			backend.EgressProgramFD(),
			"sb_share_out",
			sharedEgressFilterHandle,
			priority,
		)
		if err != nil {
			if restoreRouteLocalnet {
				_ = restoreSharedRouteLocalnet(link.Attrs().Name)
			}
			return nil, err
		}
	} else if err = removeOwnedSharedTCFilter(
		link,
		netlink.HANDLE_MIN_EGRESS,
		"sb_share_out",
		sharedEgressFilterHandle,
		priority,
	); err != nil {
		return nil, E.Cause(err, "remove stale shared-network egress filter")
	}
	ingress, err := attachSharedTCFilter(
		link,
		netlink.HANDLE_MIN_INGRESS,
		backend.IngressProgramFD(),
		"sb_share_in",
		sharedIngressFilterHandle,
		priority,
	)
	if err != nil {
		var routeErr error
		if restoreRouteLocalnet {
			routeErr = restoreSharedRouteLocalnet(link.Attrs().Name)
		}
		return nil, E.Errors(err, detachSharedTCFilter(egress), routeErr)
	}
	return &sharedTCAttachment{
		interfaceName:        link.Attrs().Name,
		ifindex:              link.Attrs().Index,
		ingress:              ingress,
		egress:               egress,
		restoreRouteLocalnet: restoreRouteLocalnet,
	}, nil
}

func sharedRouteLocalnetPath(interfaceName string) string {
	return "/proc/sys/net/ipv4/conf/" + interfaceName + "/route_localnet"
}

func enableSharedRouteLocalnet(interfaceName string) (bool, error) {
	path := sharedRouteLocalnetPath(interfaceName)
	value, err := os.ReadFile(path)
	if err != nil {
		return false, E.Cause(err, "read route_localnet for ", interfaceName)
	}
	if strings.TrimSpace(string(value)) == "1" {
		return false, nil
	}
	if strings.TrimSpace(string(value)) != "0" {
		return false, E.New("unexpected route_localnet value for ", interfaceName)
	}
	if err = os.WriteFile(path, []byte("1"), 0o644); err != nil {
		return false, E.Cause(err, "enable route_localnet for ", interfaceName)
	}
	return true, nil
}

func restoreSharedRouteLocalnet(interfaceName string) error {
	path := sharedRouteLocalnetPath(interfaceName)
	value, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return E.Cause(err, "read route_localnet for ", interfaceName)
	}
	if strings.TrimSpace(string(value)) != "1" {
		return nil
	}
	if err = os.WriteFile(path, []byte("0"), 0o644); err != nil {
		return E.Cause(err, "restore route_localnet for ", interfaceName)
	}
	return nil
}

func attachSharedTCFilter(link netlink.Link, parent uint32, programFD int, programName string, handle uint16, priority uint16) (*netlink.BpfFilter, error) {
	if programFD < 0 {
		return nil, E.New("shared-network eBPF program is unavailable")
	}
	if priority == 0 {
		priority = sharedNetworkTCPriorityDefault
	}
	filters, err := netlink.FilterList(link, parent)
	if err != nil {
		return nil, err
	}
	filterHandle := netlink.MakeHandle(0, handle)
	for _, existing := range filters {
		bpfFilter, isBPF := existing.(*netlink.BpfFilter)
		if isBPF && bpfFilter.Name == programName {
			if existing.Attrs().Handle != filterHandle || existing.Attrs().Priority != priority {
				return nil, E.New("TC filter ownership conflict on ", link.Attrs().Name, " for ", programName)
			}
			if err = netlink.FilterDel(existing); err != nil && !errors.Is(err, unix.ENOENT) {
				return nil, err
			}
			continue
		}
		if existing.Attrs().Handle == filterHandle {
			return nil, E.New("TC filter handle conflict on ", link.Attrs().Name)
		}
	}
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    parent,
			Handle:    filterHandle,
			Priority:  priority,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           programFD,
		Name:         programName,
		DirectAction: true,
	}
	if err = netlink.FilterAdd(filter); err != nil {
		return nil, err
	}
	return filter, nil
}

func removeOwnedSharedTCFilter(link netlink.Link, parent uint32, programName string, handle uint16, priority uint16) error {
	filters, err := netlink.FilterList(link, parent)
	if err != nil {
		return err
	}
	filterHandle := netlink.MakeHandle(0, handle)
	for _, existing := range filters {
		bpfFilter, isBPF := existing.(*netlink.BpfFilter)
		if isBPF && bpfFilter.Name == programName {
			if existing.Attrs().Handle != filterHandle || existing.Attrs().Priority != priority {
				return E.New("TC filter ownership conflict on ", link.Attrs().Name, " for ", programName)
			}
			if err = netlink.FilterDel(existing); err != nil && !errors.Is(err, unix.ENOENT) {
				return err
			}
			continue
		}
		if existing.Attrs().Handle == filterHandle {
			return E.New("TC filter handle conflict on ", link.Attrs().Name)
		}
	}
	return nil
}

func detachSharedTCFilter(filter *netlink.BpfFilter) error {
	if filter == nil {
		return nil
	}
	err := netlink.FilterDel(filter)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENODEV) || errors.Is(err, unix.ESRCH) {
		return nil
	}
	return err
}

func ensureClsact(link netlink.Link) error {
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return err
	}
	for _, qdisc := range qdiscs {
		if qdisc.Type() == "clsact" {
			return nil
		}
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err = netlink.QdiscAdd(qdisc); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	return nil
}

func sharedHostAddresses() ([]netip.Addr, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, E.Cause(err, "list interfaces for shared-network host bypass")
	}
	var addresses []netip.Addr
	for _, networkInterface := range interfaces {
		interfaceAddresses, addressErr := networkInterface.Addrs()
		if addressErr != nil {
			return nil, E.Cause(addressErr, "list addresses for interface ", networkInterface.Name)
		}
		for _, interfaceAddress := range interfaceAddresses {
			prefix, parseErr := netip.ParsePrefix(interfaceAddress.String())
			if parseErr == nil {
				addresses = append(addresses, prefix.Addr().Unmap())
			}
		}
	}
	return addresses, nil
}
