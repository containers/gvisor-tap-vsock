//go:build !windows

package forwarder

import "net"

// Default bind rules on Linux/macOS already refuse to share a port with
// another process unless SO_REUSEPORT is used.

func listen(network, address string) (net.Listener, error) {
	return net.Listen(network, address)
}
