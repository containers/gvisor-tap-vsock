package forwarder

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// recordingFilter records what the forwarders ask it, and refuses every
// destination when refuse is set.
type recordingFilter struct {
	mu     sync.Mutex
	calls  []string
	refuse bool
}

func (f *recordingFilter) filter(network, address string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, network+" "+address)
	if f.refuse {
		return errors.New("refused by test")
	}
	return nil
}

func (f *recordingFilter) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// guestAddr is the address the guest dials; the NAT table maps it to the
// host's loopback, so the filter must see the translated address.
var guestAddr = tcpip.AddrFrom4([4]byte{203, 0, 113, 7})

var natToLoopback = map[tcpip.Address]tcpip.Address{
	guestAddr: tcpip.AddrFrom4([4]byte{127, 0, 0, 1}),
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

		dial := func(f *recordingFilter) (net.Conn, error) {
			s := newTestStack()
			var natLock sync.Mutex
			fwd := TCP(s, natToLoopback, &natLock, false, 0, 0, f.filter)
			s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return gonet.DialContextTCP(ctx, s, tcpip.FullAddress{NIC: 1, Addr: guestAddr, Port: port}, ipv4.ProtocolNumber)
		}

		ginkgo.It("sees the destination after NAT and lets an allowed connection through", func() {
			f := &recordingFilter{}
			c, err := dial(f)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
			defer c.Close()
			buf := make([]byte, 1)
			_, err = c.Read(buf)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
			gomega.Expect(f.seen()).To(gomega.Equal([]string{"tcp 127.0.0.1:" + strconv.Itoa(int(port))}))
		})

		ginkgo.It("resets a refused connection", func() {
			f := &recordingFilter{refuse: true}
			_, err := dial(f)
			gomega.Expect(err).Should(gomega.HaveOccurred())
			gomega.Expect(f.seen()).To(gomega.HaveLen(1))
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

		send := func(f *recordingFilter) bool {
			s := newTestStack()
			var natLock sync.Mutex
			fwd := UDP(s, natToLoopback, &natLock, false, f.filter)
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

		ginkgo.It("sees the destination after NAT and forwards an allowed datagram", func() {
			f := &recordingFilter{}
			gomega.Expect(send(f)).To(gomega.BeTrue())
			gomega.Expect(f.seen()).To(gomega.ContainElement("udp 127.0.0.1:" + strconv.Itoa(int(port))))
		})

		ginkgo.It("drops a refused datagram", func() {
			f := &recordingFilter{refuse: true}
			gomega.Expect(send(f)).To(gomega.BeFalse())
			gomega.Expect(f.seen()).NotTo(gomega.BeEmpty())
		})
	})
})
