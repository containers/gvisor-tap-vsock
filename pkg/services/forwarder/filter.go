package forwarder

import (
	"net/netip"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"gvisor.dev/gvisor/pkg/tcpip"
)

func dialRequest(network string, destination, dialAddress tcpip.Address, port uint16) types.DialRequest {
	dst, _ := netip.AddrFromSlice(destination.AsSlice())
	dial, _ := netip.AddrFromSlice(dialAddress.AsSlice())
	return types.DialRequest{
		Network:     network,
		Destination: netip.AddrPortFrom(dst, port),
		DialAddress: netip.AddrPortFrom(dial, port),
	}
}
