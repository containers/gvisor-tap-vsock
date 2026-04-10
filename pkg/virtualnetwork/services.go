package virtualnetwork

import (
	"net"
	"net/http"
	"strings"
	"sync"

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
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

func addServices(configuration *types.Configuration, s *stack.Stack, ipPool *tap.IPPool) (http.Handler, *forwarder.SharedFilter, error) {
	var natLock sync.Mutex
	translation := parseNATTable(configuration)

	filter := forwarder.NewSharedFilter(configuration.NetworkPolicy)
	tcpForwarder := forwarder.TCP(s, translation, &natLock, configuration.Ec2MetadataAccess, filter)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
	udpForwarder := forwarder.UDP(s, translation, &natLock, filter)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)

	dnsMux, err := dnsServer(configuration, s, filter)
	if err != nil {
		return nil, nil, err
	}

	dhcpMux, err := dhcpServer(configuration, s, ipPool)
	if err != nil {
		return nil, nil, err
	}

	forwarderMux, err := forwardHostVM(configuration, s)
	if err != nil {
		return nil, nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("/forwarder/", http.StripPrefix("/forwarder", forwarderMux))
	mux.Handle("/dhcp/", http.StripPrefix("/dhcp", dhcpMux))
	mux.Handle("/dns/", http.StripPrefix("/dns", dnsMux))
	mux.Handle("/network/", http.StripPrefix("/network", filter.Mux()))
	return mux, filter, nil
}

func parseNATTable(configuration *types.Configuration) map[tcpip.Address]tcpip.Address {
	translation := make(map[tcpip.Address]tcpip.Address)
	for source, destination := range configuration.NAT {
		translation[tcpip.AddrFrom4Slice(net.ParseIP(source).To4())] = tcpip.AddrFrom4Slice(net.ParseIP(destination).To4())
	}
	return translation
}

func dnsServer(configuration *types.Configuration, s *stack.Stack, networkFilter *forwarder.SharedFilter) (http.Handler, error) {
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

	var dnsPolicy *types.DNSPolicy
	if configuration.NetworkPolicy != nil {
		dnsPolicy = configuration.NetworkPolicy.DNSPolicy
	}
	server, err := dns.New(udpConn, tcpLn, configuration.DNS, dnsPolicy, networkFilter)
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
	return server.Mux(), nil
}

func dhcpServer(configuration *types.Configuration, s *stack.Stack, ipPool *tap.IPPool) (http.Handler, error) {
	server, err := dhcp.New(configuration, s, ipPool)
	if err != nil {
		return nil, err
	}
	go func() {
		log.Error(server.Serve())
	}()
	return server.Mux(), nil
}

func forwardHostVM(configuration *types.Configuration, s *stack.Stack) (http.Handler, error) {
	fw := forwarder.NewPortsForwarder(s)
	for local, remote := range configuration.Forwards {
		if strings.HasPrefix(local, "udp:") {
			if err := fw.Expose(types.UDP, strings.TrimPrefix(local, "udp:"), remote); err != nil {
				return nil, err
			}
		} else {
			if err := fw.Expose(types.TCP, local, remote); err != nil {
				return nil, err
			}
		}
	}
	return fw.Mux(), nil
}
