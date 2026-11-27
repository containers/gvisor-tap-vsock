package forwarder

import (
	"net/netip"
	"sync"

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

// translate returns the address the forwarders dial for addr, after NAT
// translation.
func translate(nat map[tcpip.Address]tcpip.Address, natLock *sync.Mutex, addr tcpip.Address) tcpip.Address {
	natLock.Lock()
	defer natLock.Unlock()
	if replaced, ok := nat[addr]; ok {
		return replaced
	}
	return addr
}
