package tap

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
)

func TestRaBufSimple(t *testing.T) {
	srcMAC := tcpip.LinkAddress(net.HardwareAddr{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xdd})
	dstMAC := tcpip.LinkAddress(net.HardwareAddr{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee})
	gatewayIP := tcpip.AddrFrom16Slice(net.ParseIP("fe80::1"))
	routerLifetime := uint16(1000)

	pkt, err := raBufSimple(srcMAC, dstMAC, gatewayIP, routerLifetime)
	require.NoError(t, err)
	require.NotNil(t, pkt, "raBufSimple should return a non-nil packet")
	defer pkt.DecRef()

	// Verify packet is not empty
	pktData := pkt.ToView().AsSlice()
	assert.Greater(t, len(pktData), 0, "packet should have data")

	// The packet should contain Ethernet + IPv6 + ICMPv6 headers
	assert.GreaterOrEqual(t, len(pktData), header.EthernetMinimumSize, "packet should be at least Ethernet header size")
}

func TestRaBufWithOptions(t *testing.T) {
	srcMAC := tcpip.LinkAddress(net.HardwareAddr{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xdd})
	dstMAC := tcpip.LinkAddress(net.HardwareAddr{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee})
	gatewayIP := tcpip.AddrFrom16Slice(net.ParseIP("fe80::1"))
	routerLifetime := uint16(1800)

	// Test with empty options
	pkt, err := raBufWithOpts(srcMAC, dstMAC, gatewayIP, routerLifetime, header.NDPOptionsSerializer{})
	require.NoError(t, err)
	require.NotNil(t, pkt, "raBufWithOpts should return a non-nil packet")
	defer pkt.DecRef()

	pktData := pkt.ToView().AsSlice()
	assert.Greater(t, len(pktData), 0, "packet should have data")
}

func TestRaBufFull(t *testing.T) {
	srcMAC := tcpip.LinkAddress(net.HardwareAddr{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xdd})
	dstMAC := tcpip.LinkAddress(net.HardwareAddr{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee})
	gatewayIP := tcpip.AddrFrom16Slice(net.ParseIP("fe80::1"))
	routerLifetime := uint16(1000)

	tests := []struct {
		name                string
		managedAddress      bool
		otherConfigurations bool
		prf                 header.NDPRoutePreference
	}{
		{
			name:                "default settings",
			managedAddress:      false,
			otherConfigurations: false,
			prf:                 0,
		},
		{
			name:                "managed address flag set",
			managedAddress:      true,
			otherConfigurations: false,
			prf:                 0,
		},
		{
			name:                "other configurations flag set",
			managedAddress:      false,
			otherConfigurations: true,
			prf:                 0,
		},
		{
			name:                "both flags set",
			managedAddress:      true,
			otherConfigurations: true,
			prf:                 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt, err := raBuf(srcMAC, dstMAC, gatewayIP, routerLifetime, tt.managedAddress, tt.otherConfigurations, tt.prf, header.NDPOptionsSerializer{})
			require.NoError(t, err)
			require.NotNil(t, pkt, "raBuf should return a non-nil packet")
			defer pkt.DecRef()

			pktData := pkt.ToView().AsSlice()
			assert.Greater(t, len(pktData), 0, "packet should have data")
		})
	}
}

func TestIsIPv6RouterSolicitation(t *testing.T) {
	// Create a mock Router Solicitation packet
	// Ethernet header (14 bytes) + IPv6 header (40 bytes) + ICMPv6 header (8+ bytes)

	srcMAC := net.HardwareAddr{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee}
	dstMAC := net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0x02} // IPv6 all-routers multicast

	// Build Ethernet header
	eth := make([]byte, header.EthernetMinimumSize)
	ethHdr := header.Ethernet(eth)
	ethHdr.Encode(&header.EthernetFields{
		SrcAddr: tcpip.LinkAddress(srcMAC),
		DstAddr: tcpip.LinkAddress(dstMAC),
		Type:    ipv6.ProtocolNumber,
	})

	// Build IPv6 header
	ipv6Hdr := make([]byte, header.IPv6MinimumSize)
	ip := header.IPv6(ipv6Hdr)
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     8, // ICMPv6 Router Solicitation minimum size
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          255,
		SrcAddr:           tcpip.AddrFrom16Slice(net.ParseIP("fe80::1")),
		DstAddr:           tcpip.AddrFrom16Slice(net.ParseIP("ff02::2")), // All routers
	})

	// Build ICMPv6 Router Solicitation
	icmpHdr := make([]byte, 8) // Minimum RS size
	icmpv6 := header.ICMPv6(icmpHdr)
	icmpv6.SetType(header.ICMPv6RouterSolicit)
	icmpv6.SetCode(0)
	// Checksum would be set properly in real packet

	// Combine all headers
	packet := append(eth, ipv6Hdr...)
	packet = append(packet, icmpHdr...)

	// Parse and verify
	parsedEth := header.Ethernet(packet)
	assert.Equal(t, ipv6.ProtocolNumber, parsedEth.Type(), "Ethernet type should be IPv6")

	networkLayer := header.IPv6(packet[header.EthernetMinimumSize:])
	assert.Equal(t, header.ICMPv6ProtocolNumber, networkLayer.TransportProtocol(), "Transport protocol should be ICMPv6")

	transportLayer := header.ICMPv6(networkLayer.Payload())
	assert.Equal(t, header.ICMPv6RouterSolicit, transportLayer.Type(), "ICMPv6 type should be Router Solicitation")
}

func TestIsIPv6NeighborAdvertisement(t *testing.T) {
	// Create a mock Neighbor Advertisement packet
	srcMAC := net.HardwareAddr{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xdd}
	dstMAC := net.HardwareAddr{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee}

	// Build Ethernet header
	eth := make([]byte, header.EthernetMinimumSize)
	ethHdr := header.Ethernet(eth)
	ethHdr.Encode(&header.EthernetFields{
		SrcAddr: tcpip.LinkAddress(srcMAC),
		DstAddr: tcpip.LinkAddress(dstMAC),
		Type:    ipv6.ProtocolNumber,
	})

	// Build IPv6 header
	ipv6Hdr := make([]byte, header.IPv6MinimumSize)
	ip := header.IPv6(ipv6Hdr)
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     24, // ICMPv6 Neighbor Advertisement size
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          255,
		SrcAddr:           tcpip.AddrFrom16Slice(net.ParseIP("fe80::1")),
		DstAddr:           tcpip.AddrFrom16Slice(net.ParseIP("fe80::2")),
	})

	// Build ICMPv6 Neighbor Advertisement
	// NA format: 4 bytes flags + 16 bytes target address = 20 bytes minimum (+ 4 for ICMPv6 header = 24 total payload)
	icmpHdr := make([]byte, 24)
	icmpv6 := header.ICMPv6(icmpHdr)
	icmpv6.SetType(header.ICMPv6NeighborAdvert)
	icmpv6.SetCode(0)

	// Combine all headers
	packet := append(eth, ipv6Hdr...)
	packet = append(packet, icmpHdr...)

	// Parse and verify
	parsedEth := header.Ethernet(packet)
	assert.Equal(t, ipv6.ProtocolNumber, parsedEth.Type(), "Ethernet type should be IPv6")

	networkLayer := header.IPv6(packet[header.EthernetMinimumSize:])
	assert.Equal(t, header.ICMPv6ProtocolNumber, networkLayer.TransportProtocol(), "Transport protocol should be ICMPv6")

	transportLayer := header.ICMPv6(networkLayer.Payload())
	assert.Equal(t, header.ICMPv6NeighborAdvert, transportLayer.Type(), "ICMPv6 type should be Neighbor Advertisement")
}

func TestIPv6AddressParsing(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		isValid bool
	}{
		{"link-local", "fe80::1", true},
		{"loopback", "::1", true},
		{"all-nodes multicast", "ff02::1", true},
		{"all-routers multicast", "ff02::2", true},
		{"ULA address", "fd00::1", true},
		{"global unicast", "2001:db8::1", true},
		{"empty", "", false},
		{"invalid", "not-an-ip", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.input)
			if tt.isValid {
				assert.NotNil(t, ip, "should parse valid IPv6 address: %s", tt.input)
				if ip != nil {
					// Verify we can create a tcpip.Address from it
					addr := tcpip.AddrFrom16Slice(ip)
					assert.Equal(t, 16, addr.Len(), "IPv6 address should be 16 bytes")
				}
			} else {
				// For invalid addresses, net.ParseIP returns nil
				// which would cause tcpip.AddrFrom16Slice to panic
				assert.Nil(t, ip, "should not parse invalid address: %s", tt.input)
			}
		})
	}
}

func TestMulticastMACAddress(t *testing.T) {
	tests := []struct {
		name        string
		mac         net.HardwareAddr
		isMulticast bool
	}{
		{"all-nodes multicast", net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0x01}, true},
		{"all-routers multicast", net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0x02}, true},
		{"unicast", net.HardwareAddr{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee}, false},
		{"broadcast", net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			linkAddr := tcpip.LinkAddress(tt.mac)
			isMulticast := header.IsMulticastEthernetAddress(linkAddr)
			assert.Equal(t, tt.isMulticast, isMulticast, "multicast detection for %s", tt.name)
		})
	}
}
