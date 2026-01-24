package virtualnetwork

import (
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/containers/gvisor-tap-vsock/pkg/services/dhcp"
	"github.com/containers/gvisor-tap-vsock/pkg/services/dhcpv6"
	"github.com/containers/gvisor-tap-vsock/pkg/services/dns"
	"github.com/containers/gvisor-tap-vsock/pkg/services/forwarder"
	"github.com/containers/gvisor-tap-vsock/pkg/tap"
	"github.com/containers/gvisor-tap-vsock/pkg/types"
	log "github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

func addServices(configuration *types.Configuration, s *stack.Stack, ipPool *tap.IPPool, ipv6Pool *tap.IPPool) (http.Handler, error) {
	var natLock sync.Mutex
	translation := parseNATTable(configuration)

	tcpForwarder := forwarder.TCP(s, translation, &natLock, configuration.Ec2MetadataAccess)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
	udpForwarder := forwarder.UDP(s, translation, &natLock)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)

	dnsMux, err := dnsServer(configuration, s)
	if err != nil {
		return nil, err
	}

	dhcpMux, err := dhcpServer(configuration, s, ipPool)
	if err != nil {
		return nil, err
	}

	var dhcpv6Mux http.Handler
	if ipv6Pool != nil {
		dhcpv6Mux, err = dhcpv6Server(configuration, s, ipv6Pool)
		if err != nil {
			return nil, err
		}
	}

	forwarderMux, err := forwardHostVM(configuration, s)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("/forwarder/", http.StripPrefix("/forwarder", forwarderMux))
	mux.Handle("/dhcp/", http.StripPrefix("/dhcp", dhcpMux))
	if dhcpv6Mux != nil {
		mux.Handle("/dhcpv6/", http.StripPrefix("/dhcpv6", dhcpv6Mux))
	}
	mux.Handle("/dns/", http.StripPrefix("/dns", dnsMux))
	return mux, nil
}

func parseNATTable(configuration *types.Configuration) map[tcpip.Address]tcpip.Address {
	translation := make(map[tcpip.Address]tcpip.Address)
	for source, destination := range configuration.NAT {
		translation[tcpip.AddrFrom4Slice(net.ParseIP(source).To4())] = tcpip.AddrFrom4Slice(net.ParseIP(destination).To4())
	}
	return translation
}

func dnsServer(configuration *types.Configuration, s *stack.Stack) (http.Handler, error) {
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

	if configuration.GatewayIPv6 != "" {
		gatewayIPv6 := net.ParseIP(configuration.GatewayIPv6)
		if gatewayIPv6 != nil {
			udpConn6, err := gonet.DialUDP(s, &tcpip.FullAddress{
				NIC:  1,
				Addr: tcpip.AddrFrom16Slice(gatewayIPv6.To16()),
				Port: uint16(53),
			}, nil, ipv6.ProtocolNumber)
			if err != nil {
				log.Warnf("dns: failed to bind IPv6 UDP on %s: %v", gatewayIPv6, err)
			} else {
				server6, err := dns.New(udpConn6, nil, configuration.DNS)
				if err != nil {
					log.Warnf("dns: failed to create IPv6 server: %v", err)
				} else {
					go func() {
						if err := server6.Serve(); err != nil {
							log.Error(err)
						}
					}()
					log.Infof("dns: listening on [%s]:53 (IPv6 UDP)", gatewayIPv6)
				}
			}

			tcpLn6, err := gonet.ListenTCP(s, tcpip.FullAddress{
				NIC:  1,
				Addr: tcpip.AddrFrom16Slice(gatewayIPv6.To16()),
				Port: uint16(53),
			}, ipv6.ProtocolNumber)
			if err != nil {
				log.Warnf("dns: failed to bind IPv6 TCP on %s: %v", gatewayIPv6, err)
			} else {
				server6tcp, err := dns.New(nil, tcpLn6, configuration.DNS)
				if err != nil {
					log.Warnf("dns: failed to create IPv6 TCP server: %v", err)
				} else {
					go func() {
						if err := server6tcp.ServeTCP(); err != nil {
							log.Error(err)
						}
					}()
					log.Infof("dns: listening on [%s]:53 (IPv6 TCP)", gatewayIPv6)
				}
			}
		}
	}

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

func dhcpv6Server(configuration *types.Configuration, s *stack.Stack, ipv6Pool *tap.IPPool) (http.Handler, error) {
	server, err := dhcpv6.New(configuration, s, ipv6Pool)
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
