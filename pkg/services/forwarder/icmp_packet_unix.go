//go:build !windows

package forwarder

import (
	"net"
	"time"

	log "github.com/sirupsen/logrus"
	netIcmp "golang.org/x/net/icmp"
)

// createICMPConnection creates an ICMP connection using unprivileged ICMP sockets (udp4) on Linux/macOS.
func createICMPConnection() (*netIcmp.PacketConn, error) {
	conn, err := netIcmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		log.Debugf("Failed to create ICMP connection: %v", err)
		return nil, err
	}

	// Set read deadline
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		conn.Close()
		log.Debugf("Failed to set read deadline: %v", err)
		return nil, err
	}

	return conn, nil
}

// createDestinationAddr creates a destination address for Unix unprivileged sockets.
func createDestinationAddr(dstIP net.IP) net.Addr {
	// Linux/macOS use net.UDPAddr for unprivileged sockets
	return &net.UDPAddr{IP: dstIP, Port: 0}
}

// extractICMPData extracts ICMP data from the received bytes.
// On Linux/macOS unprivileged sockets, it returns the data as-is.
func extractICMPData(replyBytes []byte) ([]byte, error) {
	// Linux/macOS unprivileged sockets return just the ICMP data
	return replyBytes, nil
}
