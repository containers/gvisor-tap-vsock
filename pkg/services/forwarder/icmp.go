package forwarder

import (
	"regexp"
	"sync"

	"github.com/containers/gvisor-tap-vsock/pkg/services/filter"
	log "github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type Forwarder struct {
	handler func(request *ICMPForwarderRequest)
	stack   *stack.Stack
}

// icmpBlocked reports whether outbound filtering forbids forwarding a ping.
// Pings to the gateway's own address never reach the forwarder, because the
// stack answers them itself, so unlike UDP there is no gateway exception: with
// an allowlist active, every forwarded ping is blocked.
func icmpBlocked(blockAllOutbound bool, allowlistActive bool) bool {
	return blockAllOutbound || allowlistActive
}

func ICMP(s *stack.Stack, nat map[tcpip.Address]tcpip.Address, natLock *sync.Mutex, blockAllOutbound bool, outboundAllow []*regexp.Regexp, observer *filter.FilterObserver) *Forwarder {
	return NewForwarder(s, func(r *ICMPForwarderRequest) {
		localAddress := r.ID().LocalAddress

		pkt := r.Packet()
		if pkt == nil {
			log.Warningf("Dropping ICMP packet from VM (no packet data)")
			return
		}
		// HandlePacket took a reference for this request. handlePingRequest
		// releases it once the ping is forwarded; release it here if the
		// packet is dropped.
		forwarded := false
		defer func() {
			if !forwarded {
				pkt.DecRef()
			}
		}()

		// Check if this is an ICMP Echo Request (PING)
		transportHeader := pkt.TransportHeader().Slice()
		if len(transportHeader) < header.ICMPv4MinimumSize {
			log.Warningf("Dropping ICMP packet from VM (packet too short)")
			return
		}

		icmpHeader := header.ICMPv4(transportHeader)
		if icmpHeader.Type() != header.ICMPv4Echo {
			// Not a PING, drop it
			log.Warningf("Dropping ICMP packet from VM (type %d, not Echo Request)", icmpHeader.Type())
			return
		}

		// ICMP has no ports, so blocklist entries and connection records for
		// pings use port 0. Filtering uses the address the VM pinged, before
		// NAT, as the TCP and UDP forwarders do.
		if observer != nil && observer.IsBlocked("icmp", localAddress.String(), 0) {
			log.Debugf("Blocking ICMP echo to %s due to dynamic blocklist", localAddress.String())
			observer.RecordConnection("icmp", localAddress.String(), 0, "", false)
			return
		}
		// Evaluated per request: the dynamic allowlist can change at runtime.
		if icmpBlocked(blockAllOutbound, filter.AllowlistActive(outboundAllow, observer)) {
			if blockAllOutbound {
				log.Debugf("Blocking outbound ICMP echo to %s (blockAllOutbound=true)", localAddress.String())
			} else {
				log.Debugf("Blocking outbound ICMP echo to %s (outboundAllow active)", localAddress.String())
			}
			if observer != nil {
				observer.RecordConnection("icmp", localAddress.String(), 0, "", false)
			}
			return
		}
		if observer != nil {
			observer.RecordConnection("icmp", localAddress.String(), 0, "", true)
		}

		// Apply NAT translation if needed
		natLock.Lock()
		if replaced, ok := nat[localAddress]; ok {
			localAddress = replaced
		}
		natLock.Unlock()

		// This is a PING request - forward it using unprivileged ICMP sockets
		forwarded = true
		go handlePingRequest(s, r, localAddress, icmpHeader, pkt)
	})
}

// HandlePacket passes the handler every packet sent to an address that the
// stack does not own.
//
// This function is expected to be passed as an argument to the
// stack.SetTransportProtocolHandler function.
func (f *Forwarder) HandlePacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	// gvisor answers an echo request itself unless it arrived on a temporary
	// address, which promiscuous mode creates for each address that the stack
	// does not own. Forwarding a request that gvisor answers would give the VM
	// a second reply.
	if !pkt.NetworkPacketInfo.LocalAddressTemporary {
		return true
	}
	f.handler(NewICMPForwarderRequest(f.stack, id, pkt.IncRef()))
	return true
}

// NewForwarder allocates and initializes a new forwarder.
func NewForwarder(s *stack.Stack, handler func(*ICMPForwarderRequest)) *Forwarder {
	return &Forwarder{
		stack:   s,
		handler: handler,
	}
}
