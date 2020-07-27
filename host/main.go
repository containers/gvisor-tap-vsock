package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"

	log "github.com/golang/glog"
	"github.com/google/tcpproxy"
	"github.com/linuxkit/virtsock/pkg/hvsock"
	"github.com/mdlayher/vsock"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	subnet     = "192.168.127.0"
	subnetMask = "255.255.255.0"

	gateway           = "192.168.127.1"
	gatewayMacAddress = "\x5A\x94\xEF\xE4\x0C\xDD"
)

var (
	windows bool
	debug   bool
)

func main() {
	flag.BoolVar(&windows, "windows", false, "windows")
	flag.BoolVar(&debug, "debug", false, "debug")
	flag.Parse()

	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	stack, err := createStack()
	if err != nil {
		return err
	}

	if err := addServices(stack); err != nil {
		return err
	}

	stack.Wait()
	return nil
}

func addServices(s *stack.Stack) error {
	forwardTCPPackets(s)
	forwardUDPPackets(s)
	return sampleHTTPServer(s)
}

func sampleHTTPServer(s *stack.Stack) error {
	ln, err := gonet.ListenTCP(s, tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.Address(net.ParseIP(gateway).To4()),
		Port: uint16(80),
	}, ipv4.ProtocolNumber)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`Hello world`))
	})
	go http.Serve(ln, mux)
	return nil
}

func forwardTCPPackets(s *stack.Stack) {
	fwd := tcp.NewForwarder(s, 30000, 10, func(r *tcp.ForwarderRequest) {
		outbound, err := net.Dial("tcp", fmt.Sprintf("%s:%d", r.ID().LocalAddress, r.ID().LocalPort))
		if err != nil {
			log.Errorf("net.Dial() = %v", err)
			r.Complete(true)
			return
		}

		var wq waiter.Queue
		ep, tcpErr := r.CreateEndpoint(&wq)
		if tcpErr != nil {
			log.Errorf("r.CreateEndpoint() = %v", tcpErr)
			return
		}
		r.Complete(false)

		remote := tcpproxy.DialProxy{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return outbound, nil
			},
		}
		remote.HandleConn(gonet.NewTCPConn(&wq, ep))
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
}

func forwardUDPPackets(s *stack.Stack) {
	fwd := udp.NewForwarder(s, func(r *udp.ForwarderRequest) {
		outbound, err := net.Dial("udp", fmt.Sprintf("%s:%d", r.ID().LocalAddress, r.ID().LocalPort))
		if err != nil {
			log.Errorf("net.Dial() = %v", err)
			return
		}

		var wq waiter.Queue
		ep, tcpErr := r.CreateEndpoint(&wq)
		if tcpErr != nil {
			log.Errorf("r.CreateEndpoint() = %v", tcpErr)
			return
		}

		go pipe(gonet.NewUDPConn(s, &wq, ep), outbound)
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, fwd.HandlePacket)
}

func createStack() (*stack.Stack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{
			ipv4.NewProtocol(),
			arp.NewProtocol(),
		},
		TransportProtocols: []stack.TransportProtocol{
			tcp.NewProtocol(),
			udp.NewProtocol(),
			icmp.NewProtocol4(),
		},
	})

	ln, err := listen()
	if err != nil {
		return nil, err
	}

	endpoint := &TapLinkEndpoint{
		Listener:            ln,
		Debug:               debug,
		MaxTransmissionUnit: 1500,
		Mac:                 tcpip.LinkAddress(gatewayMacAddress),
	}

	if err := s.CreateNIC(1, endpoint); err != nil {
		return nil, errors.New(err.String())
	}

	if err := s.AddAddress(1, arp.ProtocolNumber, "arp"); err != nil {
		return nil, errors.New(err.String())
	}

	if err := s.AddAddress(1, ipv4.ProtocolNumber, tcpip.Address(net.ParseIP(gateway).To4())); err != nil {
		return nil, errors.New(err.String())
	}

	s.SetPromiscuousMode(1, true)

	subnet, err := tcpip.NewSubnet(tcpip.Address(net.ParseIP(subnet).To4()), tcpip.AddressMask(net.ParseIP(subnetMask).To4()))
	if err != nil {
		return nil, err
	}
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: subnet,
			Gateway:     "",
			NIC:         1,
		},
	})
	return s, nil
}

func listen() (net.Listener, error) {
	if windows {
		svcid, err := hvsock.GUIDFromString(fmt.Sprintf("%08x-FACB-11E6-BD58-64006A7986D4", 1024))
		if err != nil {
			return nil, err
		}
		return hvsock.Listen(hvsock.Addr{
			VMID:      hvsock.GUIDWildcard,
			ServiceID: svcid,
		})
	}
	return vsock.Listen(1024)
}
