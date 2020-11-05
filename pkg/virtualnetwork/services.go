package virtualnetwork

import (
	"context"
	"net"
	"strconv"
	"strings"

	"github.com/code-ready/gvisor-tap-vsock/pkg/services/dns"
	"github.com/code-ready/gvisor-tap-vsock/pkg/services/forwarder"
	"github.com/code-ready/gvisor-tap-vsock/pkg/types"
	"github.com/google/tcpproxy"
	log "github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

func addServices(configuration *types.Configuration, s *stack.Stack) error {
	tcpForwarder := forwarder.TCP(s)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
	udpForwarder := forwarder.UDP(s)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)

	go func() {
		if err := dnsServer(configuration, s); err != nil {
			log.Error(err)
		}
	}()
	return forwardHostVM(configuration, s)
}

func dnsServer(configuration *types.Configuration, s *stack.Stack) error {
	udpConn, err := gonet.DialUDP(s, &tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.Address(net.ParseIP(configuration.GatewayIP).To4()),
		Port: uint16(53),
	}, nil, ipv4.ProtocolNumber)
	if err != nil {
		return err
	}

	return dns.Serve(udpConn, configuration.DNS)
}

func forwardHostVM(configuration *types.Configuration, s *stack.Stack) error {
	for dst, src := range configuration.Forwards {
		split := strings.Split(src, ":")
		port, err := strconv.Atoi(split[1])
		if err != nil {
			return err
		}
		var p tcpproxy.Proxy
		p.AddRoute(dst, &tcpproxy.DialProxy{
			Addr: src,
			DialContext: func(ctx context.Context, network, addr string) (conn net.Conn, e error) {
				return gonet.DialTCP(s, tcpip.FullAddress{
					NIC:  1,
					Addr: tcpip.Address(net.ParseIP(split[0]).To4()),
					Port: uint16(port),
				}, ipv4.ProtocolNumber)
			},
		})
		if err := p.Start(); err != nil {
			return err
		}
		go func() {
			if err := p.Wait(); err != nil {
				log.Error(err)
			}
		}()
	}
	return nil
}
