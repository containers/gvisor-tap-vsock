package forwarder

import (
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/services/filter"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/loopback"
	"gvisor.dev/gvisor/pkg/tcpip/link/nested"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
)

// captureEndpoint is a link endpoint that hands every packet the stack writes
// to the test instead of delivering it anywhere.
type captureEndpoint struct {
	nested.Endpoint
	written chan *stack.PacketBuffer
}

func newCaptureEndpoint() *captureEndpoint {
	e := &captureEndpoint{written: make(chan *stack.PacketBuffer, 10)}
	e.Init(loopback.New(), e)
	return e
}

func (e *captureEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return 0
}

func (e *captureEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	for _, pkt := range pkts.AsSlice() {
		e.written <- pkt.IncRef()
	}
	return pkts.Len(), nil
}

// echoRequest builds an IPv4 ICMP echo request from src to dst.
func echoRequest(src, dst tcpip.Address, ident, seq uint16) *stack.PacketBuffer {
	const payload = "ping"
	const size = header.IPv4MinimumSize + header.ICMPv4MinimumSize + len(payload)
	buf := make([]byte, size)

	ip := header.IPv4(buf)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(size),
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     src,
		DstAddr:     dst,
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	icmpHdr := header.ICMPv4(ip.Payload())
	icmpHdr.SetType(header.ICMPv4Echo)
	icmpHdr.SetIdent(ident)
	icmpHdr.SetSequence(seq)
	copy(icmpHdr.Payload(), payload)
	icmpHdr.SetChecksum(^checksum.Checksum(icmpHdr, 0))

	return stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(buf)})
}

var (
	icmpTestVMIP      = tcpip.AddrFrom4([4]byte{192, 168, 127, 2})
	icmpTestGatewayIP = tcpip.AddrFrom4([4]byte{192, 168, 127, 1})
	icmpTestHostIP    = tcpip.AddrFrom4([4]byte{192, 168, 127, 254})
)

// newICMPForwardingStack returns the capture endpoint of a stack set up like
// the virtual network's, with the ICMP forwarder that newForwarder returns.
func newICMPForwardingStack(newForwarder func(s *stack.Stack) *Forwarder) *captureEndpoint {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{icmp.NewProtocol4},
	})
	ginkgo.DeferCleanup(s.Close)
	ep := newCaptureEndpoint()
	gomega.Expect(s.CreateNIC(1, ep)).To(gomega.BeNil())
	gomega.Expect(s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: icmpTestGatewayIP.WithPrefix(),
	}, stack.AddressProperties{})).To(gomega.BeNil())
	s.SetSpoofing(1, true)
	s.SetPromiscuousMode(1, true)
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	s.SetTransportProtocolHandler(icmp.ProtocolNumber4, newForwarder(s).HandlePacket)
	return ep
}

var _ = ginkgo.Describe("ICMP forwarding", func() {
	vmIP := icmpTestVMIP
	gatewayIP := icmpTestGatewayIP
	hostIP := icmpTestHostIP

	ginkgo.BeforeEach(func() {
		// The forwarder pings the host through an ICMP socket, which Linux allows
		// only for the groups in net.ipv4.ping_group_range and Windows only for
		// administrators. CI widens that range and sets REQUIRE_ICMP_SOCKET,
		// so there the tests fail instead of skipping.
		conn, err := createICMPConnection()
		if err != nil {
			if os.Getenv("REQUIRE_ICMP_SOCKET") != "" {
				ginkgo.Fail("cannot open an ICMP socket: " + err.Error())
			}
			ginkgo.Skip("cannot open an ICMP socket: " + err.Error())
		}
		conn.Close()

		// The forwarder logs why a ping failed only at debug level.
		level := log.GetLevel()
		log.SetLevel(log.DebugLevel)
		ginkgo.DeferCleanup(log.SetLevel, level)
	})

	// newForwardingStack returns the capture endpoint of a stack set up like the
	// virtual network's, with the ICMP forwarder applying nat.
	newForwardingStack := func(nat map[tcpip.Address]tcpip.Address) *captureEndpoint {
		return newICMPForwardingStack(func(s *stack.Stack) *Forwarder {
			return ICMP(s, nat, &sync.Mutex{}, false, nil, nil)
		})
	}

	// The VM pings an address that NAT maps to the host's loopback. The host
	// answers the translated address, but the VM must see the reply come from
	// the address that it pinged, because Linux drops a packet arriving on eth0
	// with a loopback source.
	ginkgo.It("should reply from the address the VM pinged, not the NAT target", func() {
		ep := newForwardingStack(map[tcpip.Address]tcpip.Address{hostIP: header.IPv4Loopback})

		ep.DeliverNetworkPacket(ipv4.ProtocolNumber, echoRequest(vmIP, hostIP, 25943, 1))

		var reply *stack.PacketBuffer
		gomega.Eventually(ep.written, 5*time.Second).Should(gomega.Receive(&reply), "no echo reply written to the VM")
		defer reply.DecRef()

		ip := header.IPv4(reply.ToView().AsSlice())
		gomega.Expect(ip.SourceAddress()).To(gomega.Equal(hostIP))
		gomega.Expect(ip.DestinationAddress()).To(gomega.Equal(vmIP))
		icmpHdr := header.ICMPv4(ip.Payload())
		gomega.Expect(icmpHdr.Type()).To(gomega.Equal(header.ICMPv4EchoReply))
		gomega.Expect(icmpHdr.Ident()).To(gomega.Equal(uint16(25943)))
		gomega.Expect(icmpHdr.Sequence()).To(gomega.Equal(uint16(1)))
	})

	// Lima maps the gateway's own address to the host's loopback. The stack
	// answers pings to its own addresses, so the forwarder must leave them
	// alone, or the VM gets a second reply to every ping.
	ginkgo.It("should leave pings to the gateway's own address to the stack", func() {
		ep := newForwardingStack(map[tcpip.Address]tcpip.Address{gatewayIP: header.IPv4Loopback})

		ep.DeliverNetworkPacket(ipv4.ProtocolNumber, echoRequest(vmIP, gatewayIP, 25943, 1))

		var reply *stack.PacketBuffer
		gomega.Eventually(ep.written, 5*time.Second).Should(gomega.Receive(&reply), "no echo reply written to the VM")
		defer reply.DecRef()
		gomega.Expect(header.IPv4(reply.ToView().AsSlice()).SourceAddress()).To(gomega.Equal(gatewayIP))

		gomega.Consistently(ep.written, time.Second).ShouldNot(gomega.Receive(), "second echo reply written to the VM")
	})

	ginkgo.It("should forward pings and record them when no filtering is configured", func() {
		observer := filter.NewFilterObserver(100)
		ep := newICMPForwardingStack(func(s *stack.Stack) *Forwarder {
			return ICMP(s, map[tcpip.Address]tcpip.Address{hostIP: header.IPv4Loopback}, &sync.Mutex{}, false, nil, observer)
		})

		ep.DeliverNetworkPacket(ipv4.ProtocolNumber, echoRequest(vmIP, hostIP, 25943, 1))

		var reply *stack.PacketBuffer
		gomega.Eventually(ep.written, 5*time.Second).Should(gomega.Receive(&reply), "no echo reply written to the VM")
		defer reply.DecRef()

		allowed := observer.GetConnections("allowed")
		gomega.Expect(allowed).To(gomega.HaveLen(1))
		gomega.Expect(allowed[0].Key).To(gomega.Equal(filter.ConnectionKey{Protocol: "icmp", IP: hostIP.String(), Port: 0}))
	})
})

// These pings are dropped before the forwarder opens an ICMP socket, so they
// run wherever the host allows it or not.
var _ = ginkgo.Describe("ICMP filtering", func() {
	remoteIP := tcpip.AddrFrom4([4]byte{1, 1, 1, 1})

	// expectBlocked pings remoteIP and checks that the VM gets no reply and
	// that the observer records the ping as blocked.
	expectBlocked := func(blockAllOutbound bool, outboundAllow []*regexp.Regexp, observer *filter.FilterObserver) {
		ep := newICMPForwardingStack(func(s *stack.Stack) *Forwarder {
			return ICMP(s, map[tcpip.Address]tcpip.Address{}, &sync.Mutex{}, blockAllOutbound, outboundAllow, observer)
		})

		ep.DeliverNetworkPacket(ipv4.ProtocolNumber, echoRequest(icmpTestVMIP, remoteIP, 25943, 1))

		gomega.Consistently(ep.written, time.Second).ShouldNot(gomega.Receive(), "echo reply written to the VM")
		blocked := observer.GetConnections("blocked")
		gomega.Expect(blocked).To(gomega.HaveLen(1))
		gomega.Expect(blocked[0].Key).To(gomega.Equal(filter.ConnectionKey{Protocol: "icmp", IP: remoteIP.String(), Port: 0}))
		gomega.Expect(observer.GetConnections("allowed")).To(gomega.BeEmpty())
	}

	ginkgo.It("should block pings when blockAllOutbound is set", func() {
		expectBlocked(true, nil, filter.NewFilterObserver(100))
	})

	ginkgo.It("should block pings when an outbound allowlist is active", func() {
		expectBlocked(false, []*regexp.Regexp{regexp.MustCompile(`^example\.com$`)}, filter.NewFilterObserver(100))
	})

	ginkgo.It("should block pings to an address on the dynamic blocklist", func() {
		observer := filter.NewFilterObserver(100)
		observer.AddBlocklistEntry("icmp", remoteIP.String(), 0, "test")
		expectBlocked(false, nil, observer)
	})

	ginkgo.It("should block pings to an address of a blocked domain", func() {
		observer := filter.NewFilterObserver(100)
		observer.RecordDNSResolution("evil.example", []string{remoteIP.String()})
		observer.AddDomainBlocklistEntry("evil.example", "test")
		expectBlocked(false, nil, observer)
	})

	ginkgo.It("should leave pings to the gateway's own address to the stack even when filtering", func() {
		observer := filter.NewFilterObserver(100)
		ep := newICMPForwardingStack(func(s *stack.Stack) *Forwarder {
			return ICMP(s, map[tcpip.Address]tcpip.Address{}, &sync.Mutex{}, true, nil, observer)
		})

		ep.DeliverNetworkPacket(ipv4.ProtocolNumber, echoRequest(icmpTestVMIP, icmpTestGatewayIP, 25943, 1))

		var reply *stack.PacketBuffer
		gomega.Eventually(ep.written, 5*time.Second).Should(gomega.Receive(&reply), "no echo reply written to the VM")
		defer reply.DecRef()
		gomega.Expect(header.IPv4(reply.ToView().AsSlice()).SourceAddress()).To(gomega.Equal(icmpTestGatewayIP))
		gomega.Expect(observer.GetConnections("")).To(gomega.BeEmpty())
	})
})
