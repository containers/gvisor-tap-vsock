package virtualnetwork

import (
	"context"
	"errors"
	"net"
	"strconv"

	"github.com/containers/gvisor-tap-vsock/pkg/services/forwarder"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

func (n *VirtualNetwork) Dial(network, addr string) (net.Conn, error) {
	ip, port, err := splitIPPort(network, addr)
	if err != nil {
		return nil, err
	}
	return gonet.DialTCP(n.stack, tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFrom4Slice(ip.To4()),
		Port: uint16(port),
	}, ipv4.ProtocolNumber)
}

func (n *VirtualNetwork) DialContextTCP(ctx context.Context, addr string) (net.Conn, error) {
	ip, port, err := splitIPPort("tcp", addr)
	if err != nil {
		return nil, err
	}
	return gonet.DialContextTCP(ctx, n.stack,
		tcpip.FullAddress{
			NIC:  1,
			Addr: tcpip.AddrFrom4Slice(ip.To4()),
			Port: port,
		}, ipv4.ProtocolNumber)
}

// DialContextTCPFrom is like DialContextTCP, but the connection originates
// from src in the virtual network, so that the guest sees the original client
// address instead of the gateway address.
// This is useful for TCP proxies implemented outside of PortsForwarder, which
// can pass the client address of the accepted connection as src.
// When src cannot be propagated (e.g., a loopback address, see
// forwarder.SourceBindAddr), the connection originates from the gateway as in
// DialContextTCP.
func (n *VirtualNetwork) DialContextTCPFrom(ctx context.Context, src net.Addr, addr string) (net.Conn, error) {
	ip, port, err := splitIPPort("tcp", addr)
	if err != nil {
		return nil, err
	}
	var bindAddr tcpip.FullAddress
	if a, ok := src.(*net.TCPAddr); ok {
		if b := forwarder.SourceBindAddr(a.IP, a.Port); b != nil {
			bindAddr = *b
		}
	}
	return gonet.DialTCPWithBind(ctx, n.stack, bindAddr,
		tcpip.FullAddress{
			NIC:  1,
			Addr: tcpip.AddrFrom4Slice(ip.To4()),
			Port: port,
		}, ipv4.ProtocolNumber)
}

func (n *VirtualNetwork) Listen(network, addr string) (net.Listener, error) {
	ip, port, err := splitIPPort(network, addr)
	if err != nil {
		return nil, err
	}
	return gonet.ListenTCP(n.stack, tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFrom4Slice(ip.To4()),
		Port: port,
	}, ipv4.ProtocolNumber)
}

func splitIPPort(network string, addr string) (net.IP, uint16, error) {
	if network != "tcp" {
		return nil, 0, errors.New("only tcp is supported")
	}
	host, portString, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, 0, err
	}
	port, err := strconv.ParseUint(portString, 10, 16)
	if err != nil {
		return nil, 0, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, 0, errors.New("invalid address, must be an IP")
	}
	return ip, uint16(port), nil
}
