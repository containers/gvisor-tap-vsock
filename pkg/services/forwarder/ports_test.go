package forwarder

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/loopback"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

func TestSuite(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "forwarder suite")
}

func hostIP() net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			return ipnet.IP
		}
	}
	return nil
}

var (
	gatewayIP = tcpip.AddrFrom4([4]byte{10, 0, 2, 1})
	childIP   = tcpip.AddrFrom4([4]byte{10, 0, 2, 100})
)

// newTestStack creates a gvisor stack with spoofing and promiscuous mode
// enabled, matching the configuration used by virtualnetwork.New.
func newTestStack() *stack.Stack {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	gomega.Expect(s.CreateNIC(1, loopback.New())).To(gomega.BeNil())
	for _, addr := range []tcpip.Address{gatewayIP, childIP} {
		gomega.Expect(s.AddProtocolAddress(1, tcpip.ProtocolAddress{
			Protocol:          ipv4.ProtocolNumber,
			AddressWithPrefix: addr.WithPrefix(),
		}, stack.AddressProperties{})).To(gomega.BeNil())
	}
	s.SetSpoofing(1, true)
	s.SetPromiscuousMode(1, true)
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	return s
}

// freeHostAddr returns a free "hostIP:port" address for the given network.
func freeHostAddr(network string, ip net.IP) string {
	switch network {
	case "tcp":
		ln, err := net.Listen("tcp", ip.String()+":0")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		addr := ln.Addr().String()
		ln.Close()
		return addr
	case "udp":
		conn, err := net.ListenPacket("udp", ip.String()+":0")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		addr := conn.LocalAddr().String()
		conn.Close()
		return addr
	default:
		panic("unsupported network: " + network)
	}
}

var _ = ginkgo.Describe("source IP propagation", func() {
	ginkgo.It("should propagate routable IPv4 source addresses", func() {
		bindAddr := sourceBindAddr(net.ParseIP("10.0.2.50"), 1234)
		gomega.Expect(bindAddr).ToNot(gomega.BeNil())
		gomega.Expect(bindAddr.NIC).To(gomega.Equal(tcpip.NICID(1)))
		gomega.Expect(bindAddr.Addr).To(gomega.Equal(tcpip.AddrFrom4([4]byte{10, 0, 2, 50})))
		gomega.Expect(bindAddr.Port).To(gomega.Equal(uint16(1234)))
	})

	// Loopback and unspecified sources must fall back to the default gateway
	// source: the guest replies to the source IP via the gateway, and gvisor
	// drops the reply as a martian packet when its destination is a loopback
	// address on the (non-loopback) tap NIC. This covers host-local forwards
	// such as 127.0.0.1:2222 -> 192.168.127.2:22.
	ginkgo.It("should not propagate loopback or unspecified source addresses", func() {
		gomega.Expect(sourceBindAddr(net.ParseIP("127.0.0.1"), 2222)).To(gomega.BeNil())
		gomega.Expect(sourceBindAddr(net.IPv4zero, 0)).To(gomega.BeNil())
		gomega.Expect(sourceBindAddr(net.ParseIP("::1"), 2222)).To(gomega.BeNil())
		gomega.Expect(sourceBindAddr(net.ParseIP("2001:db8::1"), 2222)).To(gomega.BeNil())
	})
})

var _ = ginkgo.Describe("port forwarding", func() {
	ginkgo.It("should preserve the client source IP for TCP", func() {
		ip := hostIP()
		if ip == nil {
			ginkgo.Skip("no non-loopback IPv4 address found")
		}

		s := newTestStack()

		childLn, err := gonet.ListenTCP(s, tcpip.FullAddress{NIC: 1, Addr: childIP, Port: 8080}, ipv4.ProtocolNumber)
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		defer childLn.Close()

		sourceAddrCh := make(chan string, 1)
		go func() {
			conn, err := childLn.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			sourceAddrCh <- conn.RemoteAddr().String()
			_, _ = io.Copy(io.Discard, conn)
		}()

		listenAddr := freeHostAddr("tcp", ip)
		fw := NewPortsForwarder(s)
		gomega.Expect(fw.Expose(types.TCP, listenAddr, "10.0.2.100:8080")).Should(gomega.Succeed())
		defer func() { _ = fw.Unexpose(types.TCP, listenAddr) }()

		conn, err := net.Dial("tcp", listenAddr)
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		clientIP := conn.LocalAddr().(*net.TCPAddr).IP.String()
		conn.Close()

		var addr string
		gomega.Eventually(sourceAddrCh).Should(gomega.Receive(&addr))
		host, _, err := net.SplitHostPort(addr)
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		gomega.Expect(host).To(gomega.Equal(clientIP),
			fmt.Sprintf("child saw %s, expected client IP %s (gateway is 10.0.2.1)", host, clientIP))
	})

	ginkgo.It("should preserve the client source IP for UDP", func() {
		ip := hostIP()
		if ip == nil {
			ginkgo.Skip("no non-loopback IPv4 address found")
		}

		s := newTestStack()

		childAddr := tcpip.FullAddress{NIC: 1, Addr: childIP, Port: 8081}
		childConn, err := gonet.DialUDP(s, &childAddr, nil, ipv4.ProtocolNumber)
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		defer childConn.Close()

		sourceAddrCh := make(chan string, 1)
		go func() {
			buf := make([]byte, 1024)
			n, from, err := childConn.ReadFrom(buf)
			if err != nil {
				return
			}
			sourceAddrCh <- from.String()
			// Echo back
			_, _ = childConn.WriteTo(buf[:n], from)
		}()

		listenAddr := freeHostAddr("udp", ip)
		fw := NewPortsForwarder(s)
		gomega.Expect(fw.Expose(types.UDP, listenAddr, "10.0.2.100:8081")).Should(gomega.Succeed())
		defer func() { _ = fw.Unexpose(types.UDP, listenAddr) }()

		clientConn, err := net.Dial("udp", listenAddr)
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		defer clientConn.Close()
		clientIP := clientConn.LocalAddr().(*net.UDPAddr).IP.String()

		_, err = clientConn.Write([]byte("hello"))
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

		// Read echo to ensure round-trip completes.
		gomega.Expect(clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))).ShouldNot(gomega.HaveOccurred())
		buf := make([]byte, 1024)
		_, err = clientConn.Read(buf)
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

		var addr string
		gomega.Eventually(sourceAddrCh).Should(gomega.Receive(&addr))
		host, _, err := net.SplitHostPort(addr)
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		gomega.Expect(host).To(gomega.Equal(clientIP),
			fmt.Sprintf("child saw %s, expected client IP %s (gateway is 10.0.2.1)", host, clientIP))
	})
})
