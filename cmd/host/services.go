package main

import (
	"context"
	"fmt"
	"net"
	"net/http"

	log "github.com/golang/glog"
	"github.com/google/tcpproxy"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

func addServices(s *stack.Stack) error {
	forwardTCPPackets(s)
	forwardUDPPackets(s)
	go func() {
		if err := dnsServer(s); err != nil {
			log.Error(err)
		}
	}()
	go func() {
		if err := forwardHostVM(s); err != nil {
			log.Error(err)
		}
	}()
	return sampleHTTPServer(s)
}

func forwardHostVM(s *stack.Stack) error {
	var p tcpproxy.Proxy
	p.AddRoute(":2222", &tcpproxy.DialProxy{
		Addr: fmt.Sprintf("%s:22", vm),
		DialContext: func(ctx context.Context, network, addr string) (conn net.Conn, e error) {
			return gonet.DialTCP(s, tcpip.FullAddress{
				NIC:  1,
				Addr: tcpip.Address(net.ParseIP(vm).To4()),
				Port: uint16(22),
			}, ipv4.ProtocolNumber)
		},
	})
	return p.Run()
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
		if _, err := w.Write([]byte(`Hello world`)); err != nil {
			log.Error(err)
		}
	})
	go func() {
		if err := http.Serve(ln, mux); err != nil {
			log.Error(err)
		}
	}()
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
