package dhcpv6

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/tap"
	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/dhcpv6/server6"
	log "github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const serverPort = 547

func handler(configuration *types.Configuration, ipPool *tap.IPPool) server6.Handler {
	return func(conn net.PacketConn, peer net.Addr, m dhcpv6.DHCPv6) {
		log.Debugf("dhcpv6: received message from %v: %v", peer, m.Type())
		msg, ok := m.(*dhcpv6.Message)
		if !ok {
			log.Errorf("dhcpv6: not a message: %v", m)
			return
		}

		var reply *dhcpv6.Message
		var err error

		switch msg.Type() {
		case dhcpv6.MessageTypeSolicit:
			log.Debugf("dhcpv6: handling Solicit from %v", peer)
			reply, err = handleSolicit(configuration, ipPool, msg)
		case dhcpv6.MessageTypeRequest, dhcpv6.MessageTypeConfirm, dhcpv6.MessageTypeRenew, dhcpv6.MessageTypeRebind:
			reply, err = handleRequest(configuration, ipPool, msg)
		case dhcpv6.MessageTypeRelease, dhcpv6.MessageTypeDecline:
			handleRelease(ipPool, msg)
			return
		case dhcpv6.MessageTypeInformationRequest:
			reply, err = handleInformationRequest(configuration, msg)
		default:
			log.Debugf("dhcpv6: unhandled message type: %v", msg.Type())
			return
		}

		if err != nil {
			log.Errorf("dhcpv6: failed to create reply: %v", err)
			return
		}

		if reply == nil {
			return
		}

		log.Debugf("dhcpv6: sending %v to %v", reply.Type(), peer)
		_, err = conn.WriteTo(reply.ToBytes(), peer)
		if err != nil {
			log.Errorf("dhcpv6: cannot reply to client: %v", err)
		}
	}
}

func handleSolicit(configuration *types.Configuration, ipPool *tap.IPPool, msg *dhcpv6.Message) (*dhcpv6.Message, error) {
	clientID := msg.GetOneOption(dhcpv6.OptionClientID)
	if clientID == nil {
		return nil, errors.New("client ID not found")
	}

	duid, err := dhcpv6.DUIDFromBytes(clientID.ToBytes()[4:])
	if err != nil {
		return nil, err
	}

	ip, err := ipPool.GetOrAssign(duid.String())
	if err != nil {
		return nil, err
	}
	log.Debugf("dhcpv6: offering IP %s to client %s", ip, duid.String())

	reply, err := dhcpv6.NewAdvertiseFromSolicit(msg)
	if err != nil {
		return nil, err
	}

	addCommonOptions(reply, configuration, net.IP(ip.AsSlice()), msg)
	return reply, nil
}

func handleRequest(configuration *types.Configuration, ipPool *tap.IPPool, msg *dhcpv6.Message) (*dhcpv6.Message, error) {
	clientID := msg.GetOneOption(dhcpv6.OptionClientID)
	if clientID == nil {
		return nil, errors.New("client ID not found")
	}

	duid, err := dhcpv6.DUIDFromBytes(clientID.ToBytes()[4:])
	if err != nil {
		return nil, err
	}

	ip, err := ipPool.GetOrAssign(duid.String())
	if err != nil {
		return nil, err
	}

	reply, err := dhcpv6.NewReplyFromMessage(msg)
	if err != nil {
		return nil, err
	}

	addCommonOptions(reply, configuration, net.IP(ip.AsSlice()), msg)
	return reply, nil
}

func handleRelease(ipPool *tap.IPPool, msg *dhcpv6.Message) {
	clientID := msg.GetOneOption(dhcpv6.OptionClientID)
	if clientID == nil {
		return
	}

	duid, err := dhcpv6.DUIDFromBytes(clientID.ToBytes()[4:])
	if err != nil {
		return
	}

	ipPool.Release(duid.String())
}

func handleInformationRequest(configuration *types.Configuration, msg *dhcpv6.Message) (*dhcpv6.Message, error) {
	reply, err := dhcpv6.NewReplyFromMessage(msg)
	if err != nil {
		return nil, err
	}

	addDNSOption(reply, configuration)

	return reply, nil
}

// addDNSOption appends a DNS server option pointing at the IPv6 gateway, but
// only when the configured gateway address is valid. Adding OptDNS(nil) would
// hand clients a bogus/empty DNS server, so an unparseable address is skipped.
func addDNSOption(reply *dhcpv6.Message, configuration *types.Configuration) {
	dnsIP := net.ParseIP(configuration.GatewayIPv6)
	if dnsIP == nil {
		log.Errorf("dhcpv6: cannot parse gateway IPv6 address %q, skipping DNS option", configuration.GatewayIPv6)
		return
	}
	reply.AddOption(dhcpv6.OptDNS(dnsIP))
}

func addCommonOptions(reply *dhcpv6.Message, configuration *types.Configuration, ip net.IP, request *dhcpv6.Message) {
	serverDUID := &dhcpv6.DUIDLL{
		HWType:        6,
		LinkLayerAddr: net.HardwareAddr{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xdd},
	}
	reply.AddOption(dhcpv6.OptServerID(serverDUID))

	// Extract client's IAID from the request (RFC 8415 requires copying it)
	var clientIAID [4]byte
	if ianaOpt := request.GetOneOption(dhcpv6.OptionIANA); ianaOpt != nil {
		if iana, ok := ianaOpt.(*dhcpv6.OptIANA); ok {
			clientIAID = iana.IaId
			log.Debugf("dhcpv6: using client IAID: %v", clientIAID)
		}
	}

	iana := &dhcpv6.OptIANA{
		IaId: clientIAID,
		T1:   time.Hour,
		T2:   2 * time.Hour,
		Options: dhcpv6.IdentityOptions{
			Options: []dhcpv6.Option{
				&dhcpv6.OptIAAddress{
					IPv6Addr:          ip,
					PreferredLifetime: 4 * time.Hour,
					ValidLifetime:     8 * time.Hour,
				},
			},
		},
	}
	reply.AddOption(iana)

	addDNSOption(reply, configuration)
}

func dial(s *stack.Stack, nic tcpip.NICID) (*gonet.UDPConn, error) {
	var wq waiter.Queue
	ep, err := s.NewEndpoint(udp.ProtocolNumber, ipv6.ProtocolNumber, &wq)
	if err != nil {
		return nil, errors.New(err.String())
	}

	if err := ep.Bind(tcpip.FullAddress{
		NIC:  nic,
		Addr: tcpip.Address{},
		Port: uint16(serverPort),
	}); err != nil {
		ep.Close()
		return nil, errors.New(err.String())
	}

	ep.SetSockOpt(&tcpip.AddMembershipOption{
		NIC:           nic,
		MulticastAddr: tcpip.AddrFrom16Slice(dhcpv6.AllDHCPRelayAgentsAndServers.To16()),
	})

	return gonet.NewUDPConn(&wq, ep), nil
}

type Server struct {
	Underlying *server6.Server
	IPPool     *tap.IPPool
}

func New(configuration *types.Configuration, s *stack.Stack, ipPool *tap.IPPool) (*Server, error) {
	log.Infof("dhcpv6: starting server on %s:%d", configuration.GatewayIPv6, serverPort)
	ln, err := dial(s, tcpip.NICID(1))
	if err != nil {
		log.Errorf("dhcpv6: failed to dial: %v", err)
		return nil, err
	}
	log.Infof("dhcpv6: listening on %s", ln.LocalAddr())

	srv, err := server6.NewServer("", nil, handler(configuration, ipPool), server6.WithConn(ln))
	if err != nil {
		return nil, err
	}

	return &Server{
		Underlying: srv,
		IPPool:     ipPool,
	}, nil
}

func (s *Server) Serve() error {
	return s.Underlying.Serve()
}

func (s *Server) Mux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/leases", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(s.IPPool.Leases())
	})
	return mux
}
