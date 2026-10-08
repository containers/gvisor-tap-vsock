package virtualnetwork

import (
	"net"
	"strings"
	"sync"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/services/dhcp"
	"github.com/containers/gvisor-tap-vsock/pkg/services/dns"
	"github.com/containers/gvisor-tap-vsock/pkg/services/forwarder"
	"github.com/containers/gvisor-tap-vsock/pkg/tap"
	"github.com/containers/gvisor-tap-vsock/pkg/types"
	log "github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

func addServices(configuration *types.Configuration, s *stack.Stack, ipPool *tap.IPPool) (*forwarder.PortsForwarder, *dns.Server, *dhcp.Server, error) {
	var natLock sync.Mutex
	translation := parseNATTable(configuration)

	tcpForwarder := forwarder.TCP(s, translation, &natLock, configuration.Ec2MetadataAccess,
		configuration.TCPMaxInFlight, time.Duration(configuration.TCPConnectTimeout)*time.Second)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
	udpForwarder := forwarder.UDP(s, translation, &natLock, configuration.Ec2MetadataAccess)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)
	icmpForwarder := forwarder.ICMP(s, translation, &natLock)
	s.SetTransportProtocolHandler(icmp.ProtocolNumber4, icmpForwarder.HandlePacket)

	dnsServer, err := createDNSServer(configuration, s)
	if err != nil {
		return nil, nil, nil, err
	}

	dhcpServer, err := createDHCPServer(configuration, s, ipPool)
	if err != nil {
		return nil, nil, nil, err
	}

	portsForwarder, err := createPortsForwarder(configuration, s)
	if err != nil {
		return nil, nil, nil, err
	}

	return portsForwarder, dnsServer, dhcpServer, nil
}

func parseNATTable(configuration *types.Configuration) map[tcpip.Address]tcpip.Address {
	translation := make(map[tcpip.Address]tcpip.Address)
	for source, destination := range configuration.NAT {
		translation[tcpip.AddrFrom4Slice(net.ParseIP(source).To4())] = tcpip.AddrFrom4Slice(net.ParseIP(destination).To4())
	}
	return translation
}

func createDNSServer(configuration *types.Configuration, s *stack.Stack) (*dns.Server, error) {
	udpConn, err := gonet.DialUDP(s, &tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFrom4Slice(net.ParseIP(configuration.GatewayIP).To4()),
		Port: uint16(53),
	}, nil, ipv4.ProtocolNumber)
	if err != nil {
		return nil, err
	}

	tcpLn, err := gonet.ListenTCP(s, tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFrom4Slice(net.ParseIP(configuration.GatewayIP).To4()),
		Port: uint16(53),
	}, ipv4.ProtocolNumber)
	if err != nil {
		return nil, err
	}

	server, err := dns.New(udpConn, tcpLn, configuration.DNS)
	if err != nil {
		return nil, err
	}

	go func() {
		if err := server.Serve(); err != nil {
			log.Error(err)
		}
	}()
	go func() {
		if err := server.ServeTCP(); err != nil {
			log.Error(err)
		}
	}()
	return server, nil
}

func createDHCPServer(configuration *types.Configuration, s *stack.Stack, ipPool *tap.IPPool) (*dhcp.Server, error) {
	server, err := dhcp.New(configuration, s, ipPool)
	if err != nil {
		return nil, err
	}
	go func() {
		log.Error(server.Serve())
	}()
	return server, nil
}

func createPortsForwarder(configuration *types.Configuration, s *stack.Stack) (*forwarder.PortsForwarder, error) {
	portsForwarder := forwarder.NewPortsForwarder(s)
	for local, remote := range configuration.Forwards {
		if after, ok := strings.CutPrefix(local, "udp:"); ok {
			if err := portsForwarder.Expose(types.UDP, after, remote); err != nil {
				return nil, err
			}
		} else {
			if err := portsForwarder.Expose(types.TCP, local, remote); err != nil {
				return nil, err
			}
		}
	}
	return portsForwarder, nil
}
