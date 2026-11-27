package dhcp

import (
	"errors"
	"math"
	"net"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/tap"
	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/server4"
	"github.com/insomniacslk/dhcp/rfc1035label"
	log "github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const serverPort = 67

func handler(configuration *types.Configuration, ipPool *tap.IPPool) server4.Handler {
	return func(conn net.PacketConn, peer net.Addr, m *dhcpv4.DHCPv4) {
		reply, err := dhcpv4.NewReplyFromRequest(m)
		if err != nil {
			log.Errorf("dhcp: cannot build reply from request: %v", err)
			return
		}

		ip, err := ipPool.GetOrAssign(m.ClientHWAddr.String())
		if err != nil {
			log.Errorf("dhcp: cannot assign ip: %v", err)
			return
		}

		_, parsedSubnet, err := net.ParseCIDR(configuration.Subnet)
		if err != nil {
			log.Errorf("dhcp: invalid subnet %v", err)
			return
		}

		reply.YourIPAddr = net.IP(ip.AsSlice())
		reply.UpdateOption(dhcpv4.OptServerIdentifier(net.ParseIP(configuration.GatewayIP)))
		reply.UpdateOption(dhcpv4.OptIPAddressLeaseTime(time.Hour))

		reply.UpdateOption(dhcpv4.Option{Code: dhcpv4.OptionSubnetMask, Value: dhcpv4.IP(parsedSubnet.Mask)})
		reply.UpdateOption(dhcpv4.Option{Code: dhcpv4.OptionRouter, Value: dhcpv4.IP(net.ParseIP(configuration.GatewayIP))})
		reply.UpdateOption(dhcpv4.Option{Code: dhcpv4.OptionDomainNameServer, Value: dhcpv4.IPs([]net.IP{net.ParseIP(configuration.GatewayIP)})})

		if configuration.BootFileName != "" {
			reply.UpdateOption(dhcpv4.OptBootFileName(configuration.BootFileName))
		}

		mtu := configuration.MTU
		if mtu < 0 || mtu > math.MaxUint16 {
			log.Errorf("dhcp: invalid MTU %d", mtu)
		} else {
			reply.UpdateOption(dhcpv4.Option{Code: dhcpv4.OptionInterfaceMTU, Value: dhcpv4.Uint16(mtu)})
		}
		switch mt := m.MessageType(); mt {
		case dhcpv4.MessageTypeDiscover:
			reply.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeOffer))
		case dhcpv4.MessageTypeRequest:
			reply.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeAck))
		case dhcpv4.MessageTypeRelease:
			log.Debugf("dhcp: unhandled message type: %v", mt)
			return
		default:
			log.Errorf("dhcp: unhandled message type: %v", mt)
			return
		}

		maxPacketSize := header.IPv4MinimumProcessableDatagramSize
		if size, err := m.MaxMessageSize(); err == nil && size >= header.IPv4MinimumProcessableDatagramSize {
			maxPacketSize = int(size)
		}
		if mtu > 0 && mtu < maxPacketSize {
			maxPacketSize = mtu
		}
		// RFC 2131's packet-size limit includes the IPv4 and UDP headers (20 and 8 bytes respectively).
		addSearchDomains(reply, configuration.DNSSearchDomains, maxPacketSize-header.IPv4MinimumSize-header.UDPMinimumSize)

		if _, err := conn.WriteTo(reply.ToBytes(), peer); err != nil {
			log.Errorf("dhcp: cannot reply to client: %v", err)
		}
	}
}

func addSearchDomains(reply *dhcpv4.DHCPv4, domains []string, maxSize int) {
	for count := len(domains); count > 0; count-- {
		reply.UpdateOption(dhcpv4.OptDomainSearch(&rfc1035label.Labels{
			Labels: domains[:count],
		}))
		if len(reply.ToBytes()) <= maxSize {
			return
		}
	}
	reply.Options.Del(dhcpv4.OptionDNSDomainSearchList)
}

func dial(s *stack.Stack, nic tcpip.NICID) (*gonet.UDPConn, error) {
	var wq waiter.Queue
	ep, err := s.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if err != nil {
		return nil, errors.New(err.String())
	}

	ep.SocketOptions().SetBroadcast(true)

	if err := ep.Bind(tcpip.FullAddress{
		NIC:  tcpip.NICID(nic),
		Addr: tcpip.Address{},
		Port: uint16(serverPort),
	}); err != nil {
		ep.Close()
		return nil, errors.New(err.String())
	}

	return gonet.NewUDPConn(&wq, ep), nil
}

type Server struct {
	Underlying *server4.Server
	IPPool     *tap.IPPool
}

func New(configuration *types.Configuration, stack *stack.Stack, ipPool *tap.IPPool) (*Server, error) {
	ln, err := dial(stack, tcpip.NICID(1))
	if err != nil {
		return nil, err
	}

	s, err := server4.NewServer("", nil, handler(configuration, ipPool), server4.WithConn(ln))
	if err != nil {
		return nil, err
	}

	return &Server{
		Underlying: s,
		IPPool:     ipPool,
	}, nil
}

func (s *Server) Serve() error {
	return s.Underlying.Serve()
}

func (s *Server) Leases() map[string]string {
	return s.IPPool.Leases()
}
