package forwarder

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"regexp"
	"sync"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/services/filter"
	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

type recordingFilter struct {
	mu     sync.Mutex
	calls  []types.DialRequest
	refuse bool
}

func (f *recordingFilter) filter(req types.DialRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, req)
	if f.refuse {
		return errors.New("refused by test")
	}
	return nil
}

func (f *recordingFilter) seen() []types.DialRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]types.DialRequest(nil), f.calls...)
}

var (
	guestIP    = netip.MustParseAddr("203.0.113.7")
	loopbackIP = netip.MustParseAddr("127.0.0.1")
	guestAddr  = tcpip.AddrFrom4(guestIP.As4())
)

var natToLoopback = map[tcpip.Address]tcpip.Address{
	guestAddr: tcpip.AddrFrom4(loopbackIP.As4()),
}

func natRequest(network string, port uint16) types.DialRequest {
	return types.DialRequest{
		Network:     network,
		Destination: netip.AddrPortFrom(guestIP, port),
		DialAddress: netip.AddrPortFrom(loopbackIP, port),
	}
}

var _ = ginkgo.Describe("dial filter", func() {
	ginkgo.Context("TCP", func() {
		var (
			ln   net.Listener
			port uint16
		)

		ginkgo.BeforeEach(func() {
			var err error
			ln, err = net.Listen("tcp", "127.0.0.1:0")
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
			port = uint16(ln.Addr().(*net.TCPAddr).Port)
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					_, _ = c.Write([]byte("x"))
					c.Close()
				}
			}()
		})

		ginkgo.AfterEach(func() { ln.Close() })

		// dialPort connects from the guest to guestAddr:dstPort through a TCP
		// forwarder with the given dial filter, outbound allowlist and filter
		// observer.
		dialPort := func(f *recordingFilter, dstPort uint16, outboundAllow []*regexp.Regexp, observer *filter.FilterObserver) (net.Conn, error) {
			s := newTestStack()
			var natLock sync.Mutex
			fwd := TCP(s, natToLoopback, &natLock, false, 0, 0, false, outboundAllow, nil, observer, f.filter)
			s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return gonet.DialContextTCP(ctx, s, tcpip.FullAddress{NIC: 1, Addr: guestAddr, Port: dstPort}, ipv4.ProtocolNumber)
		}

		dial := func(f *recordingFilter) (net.Conn, error) {
			return dialPort(f, port, nil, nil)
		}

		ginkgo.It("sees the destination before and after NAT and lets an allowed connection through", func() {
			f := &recordingFilter{}
			c, err := dial(f)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
			defer c.Close()
			buf := make([]byte, 1)
			_, err = c.Read(buf)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
			gomega.Expect(f.seen()).To(gomega.Equal([]types.DialRequest{natRequest("tcp", port)}))
		})

		ginkgo.It("resets a refused connection", func() {
			f := &recordingFilter{refuse: true}
			_, err := dial(f)
			gomega.Expect(err).Should(gomega.HaveOccurred())
			gomega.Expect(f.seen()).To(gomega.HaveLen(1))
		})

		ginkgo.It("records a refused connection as blocked in the filter observer", func() {
			observer := filter.NewFilterObserver(100)
			_, err := dialPort(&recordingFilter{refuse: true}, port, nil, observer)
			gomega.Expect(err).Should(gomega.HaveOccurred())

			blocked := observer.GetConnections("blocked")
			gomega.Expect(blocked).To(gomega.HaveLen(1))
			gomega.Expect(blocked[0].Key).To(gomega.Equal(filter.ConnectionKey{Protocol: "tcp", IP: guestIP.String(), Port: port}))
			gomega.Expect(observer.GetConnections("allowed")).To(gomega.BeEmpty())
		})

		// With an allowlist active, port 443 is accepted so the forwarder can
		// read the TLS ClientHello. A refusal by the dial filter must come
		// before that, so the guest's connect fails instead of succeeding and
		// then being closed.
		ginkgo.Context("with an outbound allowlist active", func() {
			allowlist := []*regexp.Regexp{regexp.MustCompile(`^example\.com$`)}

			ginkgo.It("resets a refused connection to port 443 before accepting it to read the ClientHello", func() {
				f := &recordingFilter{refuse: true}
				_, err := dialPort(f, 443, allowlist, nil)
				gomega.Expect(err).Should(gomega.HaveOccurred())
				// A retransmitted SYN, when the reset is slow to arrive, asks
				// the filter again; every request must be for this connection.
				gomega.Expect(f.seen()).NotTo(gomega.BeEmpty())
				gomega.Expect(f.seen()).To(gomega.HaveEach(natRequest("tcp", 443)))
			})

			ginkgo.It("accepts a connection to port 443 that the dial filter allows, to read the ClientHello", func() {
				f := &recordingFilter{}
				c, err := dialPort(f, 443, allowlist, nil)
				gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
				c.Close()
				// A retransmitted SYN, when the reset is slow to arrive, asks
				// the filter again; every request must be for this connection.
				gomega.Expect(f.seen()).NotTo(gomega.BeEmpty())
				gomega.Expect(f.seen()).To(gomega.HaveEach(natRequest("tcp", 443)))
			})
		})
	})

	ginkgo.Context("UDP", func() {
		var (
			pc   net.PacketConn
			port uint16
		)

		ginkgo.BeforeEach(func() {
			var err error
			pc, err = net.ListenPacket("udp", "127.0.0.1:0")
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
			port = uint16(pc.LocalAddr().(*net.UDPAddr).Port)
		})

		ginkgo.AfterEach(func() { pc.Close() })

		sendObserved := func(f *recordingFilter, observer *filter.FilterObserver) bool {
			s := newTestStack()
			var natLock sync.Mutex
			fwd := UDP(s, natToLoopback, &natLock, false, false, nil, nil, observer, f.filter)
			s.SetTransportProtocolHandler(udp.ProtocolNumber, fwd.HandlePacket)
			c, err := gonet.DialUDP(s, nil, &tcpip.FullAddress{NIC: 1, Addr: guestAddr, Port: port}, ipv4.ProtocolNumber)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
			defer c.Close()
			_, err = c.Write([]byte("x"))
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

			_ = pc.SetReadDeadline(time.Now().Add(time.Second))
			_, _, err = pc.ReadFrom(make([]byte, 16))
			return err == nil
		}

		send := func(f *recordingFilter) bool {
			return sendObserved(f, nil)
		}

		ginkgo.It("sees the destination before and after NAT and forwards an allowed datagram", func() {
			f := &recordingFilter{}
			gomega.Expect(send(f)).To(gomega.BeTrue())
			gomega.Expect(f.seen()).To(gomega.ContainElement(natRequest("udp", port)))
		})

		ginkgo.It("drops a refused datagram", func() {
			f := &recordingFilter{refuse: true}
			gomega.Expect(send(f)).To(gomega.BeFalse())
			gomega.Expect(f.seen()).NotTo(gomega.BeEmpty())
		})

		ginkgo.It("records a refused datagram as blocked in the filter observer", func() {
			observer := filter.NewFilterObserver(100)
			gomega.Expect(sendObserved(&recordingFilter{refuse: true}, observer)).To(gomega.BeFalse())

			blocked := observer.GetConnections("blocked")
			gomega.Expect(blocked).NotTo(gomega.BeEmpty())
			gomega.Expect(blocked[0].Key).To(gomega.Equal(filter.ConnectionKey{Protocol: "udp", IP: guestIP.String(), Port: port}))
			gomega.Expect(observer.GetConnections("allowed")).To(gomega.BeEmpty())
		})
	})
})
