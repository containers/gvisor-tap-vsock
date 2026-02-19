//go:build windows

package forwarder

import (
	"fmt"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
	netIcmp "golang.org/x/net/icmp"
)

// createICMPConnection creates an ICMP connection using privileged raw sockets (ip4:icmp) on Windows.
func createICMPConnection() (*netIcmp.PacketConn, error) {
	conn, err := netIcmp.ListenPacket("ip4:icmp", "0.0.0.0")
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

// createDestinationAddr creates a destination address for Windows raw sockets.
func createDestinationAddr(dstIP net.IP) net.Addr {
	// Windows requires net.IPAddr for raw sockets
	return &net.IPAddr{IP: dstIP}
}

// extractICMPData extracts ICMP data from the received bytes.
// On Windows with raw sockets, it skips the IP header.
func extractICMPData(replyBytes []byte) ([]byte, error) {
	// Raw sockets on Windows include the IP header, so we need to skip it
	if len(replyBytes) < 20 {
		log.Debugf("Reply packet too short: %d bytes", len(replyBytes))
		return nil, fmt.Errorf("reply packet too short: %d bytes", len(replyBytes))
	}

	// Check if it's IPv4 (first byte: version and IHL)
	version := (replyBytes[0] >> 4) & 0x0F
	if version != 4 {
		log.Debugf("Unexpected IP version: %d", version)
		return nil, fmt.Errorf("unexpected IP version: %d", version)
	}

	// Get IP header length (IHL is in the lower 4 bits of first byte, in 4-byte units)
	ihl := int(replyBytes[0]&0x0F) * 4
	if ihl < 20 || ihl > len(replyBytes) {
		log.Debugf("Invalid IP header length: %d", ihl)
		return nil, fmt.Errorf("invalid IP header length: %d", ihl)
	}

	return replyBytes[ihl:], nil
}

// getExpectedReplyIdent returns the ICMP echo identifier to expect in the reply.
// On Windows (raw sockets) the kernel preserves the ID we send.
func getExpectedReplyIdent(conn *netIcmp.PacketConn, sentIdent uint16) uint16 {
	return sentIdent
}
