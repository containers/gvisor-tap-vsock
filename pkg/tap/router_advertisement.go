package tap

import (
	"encoding/binary"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
)

// raBuf returns a valid NDP Router Advertisement with options, router
// preference and DHCPv6 configurations specified.
func raBuf(
	src, dst tcpip.LinkAddress,
	ip tcpip.Address,
	rl uint16,
	managedAddress, otherConfigurations bool,
	prf header.NDPRoutePreference,
	optSer header.NDPOptionsSerializer,
) (*stack.PacketBuffer, error) {
	const flagsByte = 1
	const routerLifetimeOffset = 2

	icmpSize := header.ICMPv6HeaderSize + header.NDPRAMinimumSize + optSer.Length()
	hdr := buffer.MakeWithView(buffer.NewView(header.EthernetMinimumSize + header.IPv6MinimumSize + icmpSize))
	pkt := header.ICMPv6(make([]byte, icmpSize))
	pkt.SetType(header.ICMPv6RouterAdvert)
	pkt.SetCode(0)
	raPayload := pkt.MessageBody()
	ra := header.NDPRouterAdvert(raPayload)
	// Populate the Router Lifetime.
	binary.BigEndian.PutUint16(raPayload[routerLifetimeOffset:], rl)
	// Populate the Managed Address flag field.
	if managedAddress {
		// The Managed Addresses flag field is the 7th bit of the flags byte.
		raPayload[flagsByte] |= 1 << 7
	}
	// Populate the Other Configurations flag field.
	if otherConfigurations {
		// The Other Configurations flag field is the 6th bit of the flags byte.
		raPayload[flagsByte] |= 1 << 6
	}
	// The Prf field is held in the flags byte.
	raPayload[flagsByte] |= byte(prf) << 3
	opts := ra.Options()
	opts.Serialize(optSer)
	pkt.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header: pkt,
		Src:    ip,
		Dst:    header.IPv6AllNodesMulticastAddress,
	}))
	if err := hdr.Prepend(buffer.NewViewWithData(pkt)); err != nil {
		return nil, err
	}

	payloadLength := icmpSize
	iph := header.IPv6(make([]byte, header.IPv6MinimumSize))
	iph.Encode(&header.IPv6Fields{
		TrafficClass:      0,
		FlowLabel:         0,
		PayloadLength:     uint16(payloadLength),
		TransportProtocol: icmp.ProtocolNumber6,
		HopLimit:          header.NDPHopLimit,
		SrcAddr:           ip,
		DstAddr:           header.IPv6AllNodesMulticastAddress,
		ExtensionHeaders:  []header.IPv6SerializableExtHdr{},
	})
	if err := hdr.Prepend(buffer.NewViewWithData(iph)); err != nil {
		return nil, err
	}

	eth := header.Ethernet(make([]byte, header.EthernetMinimumSize))
	eth.Encode(&header.EthernetFields{
		Type:    ipv6.ProtocolNumber,
		SrcAddr: src,
		DstAddr: dst,
	})
	if err := hdr.Prepend(buffer.NewViewWithData(eth)); err != nil {
		return nil, err
	}
	return stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: hdr,
	}), nil
}

// raBufWithOpts returns a valid NDP Router Advertisement with options.
//
// Note, raBufWithOpts does not populate any of the RA fields other than the
// Router Lifetime.
func raBufWithOpts(src, dst tcpip.LinkAddress, ip tcpip.Address, rl uint16, optSer header.NDPOptionsSerializer) (*stack.PacketBuffer, error) {
	return raBuf(src, dst, ip, rl, false /* managedAddress */, false /* otherConfigurations */, 0 /* prf */, optSer)
}

// raBuf returns a valid NDP Router Advertisement.
//
// Note, raBuf does not populate any of the RA fields other than the
// Router Lifetime.
func raBufSimple(src, dst tcpip.LinkAddress, ip tcpip.Address, rl uint16) (*stack.PacketBuffer, error) {
	return raBufWithOpts(src, dst, ip, rl, header.NDPOptionsSerializer{})
}
