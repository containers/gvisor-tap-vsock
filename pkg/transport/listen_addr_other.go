//go:build !windows

package transport

import "net"

// ListenAddr opens a listener on address with net.Listen.
func ListenAddr(network, address string) (net.Listener, error) {
	return net.Listen(network, address)
}

// ListenPacketAddr opens a packet listener on address with net.ListenPacket.
func ListenPacketAddr(network, address string) (net.PacketConn, error) {
	return net.ListenPacket(network, address)
}
