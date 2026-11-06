package virtualnetwork

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/loopback"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

var (
	testGatewayIP = tcpip.AddrFrom4([4]byte{10, 0, 2, 1})
	testChildIP   = tcpip.AddrFrom4([4]byte{10, 0, 2, 100})
)

// newTestNetwork creates a VirtualNetwork backed by a loopback stack with
// spoofing and promiscuous mode enabled, matching the configuration used by New.
func newTestNetwork(t *testing.T) *VirtualNetwork {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	t.Cleanup(s.Destroy)
	require.Nil(t, s.CreateNIC(1, loopback.New()))
	for _, addr := range []tcpip.Address{testGatewayIP, testChildIP} {
		require.Nil(t, s.AddProtocolAddress(1, tcpip.ProtocolAddress{
			Protocol:          ipv4.ProtocolNumber,
			AddressWithPrefix: addr.WithPrefix(),
		}, stack.AddressProperties{}))
	}
	s.SetSpoofing(1, true)
	s.SetPromiscuousMode(1, true)
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	return &VirtualNetwork{stack: s}
}

type dialFunc func(ctx context.Context, addr string) (net.Conn, error)

// dialAndGetSource dials the child and returns the source IP seen by the child.
func dialAndGetSource(t *testing.T, n *VirtualNetwork, dial dialFunc) string {
	ln, err := gonet.ListenTCP(n.stack, tcpip.FullAddress{NIC: 1, Addr: testChildIP}, ipv4.ProtocolNumber)
	require.NoError(t, err)
	defer ln.Close()

	conn, err := dial(context.Background(), ln.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	accepted, err := ln.Accept()
	require.NoError(t, err)
	defer accepted.Close()
	host, _, err := net.SplitHostPort(accepted.RemoteAddr().String())
	require.NoError(t, err)
	return host
}

func dialFrom(n *VirtualNetwork, src net.Addr) dialFunc {
	return func(ctx context.Context, addr string) (net.Conn, error) {
		return n.DialContextTCPFrom(ctx, src, addr)
	}
}

func TestDialContextTCPFrom(t *testing.T) {
	n := newTestNetwork(t)
	src := &net.TCPAddr{IP: net.ParseIP("192.168.1.50"), Port: 12345}
	assert.Equal(t, "192.168.1.50", dialAndGetSource(t, n, dialFrom(n, src)))
}

func TestDialContextTCPFromNotPropagated(t *testing.T) {
	n := newTestNetwork(t)
	// The source address chosen by the stack, without propagation
	want := dialAndGetSource(t, n, n.DialContextTCP)
	for _, src := range []net.Addr{
		nil,
		&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
		&net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 12345},
		&net.UDPAddr{IP: net.ParseIP("192.168.1.50"), Port: 12345},
	} {
		assert.Equal(t, want, dialAndGetSource(t, n, dialFrom(n, src)), "src=%v", src)
	}
}
