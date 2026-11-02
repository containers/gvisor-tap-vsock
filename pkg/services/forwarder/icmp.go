package forwarder

import (
	"sync"

	log "github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type Forwarder struct {
	handler func(request *ICMPForwarderRequest)
	stack   *stack.Stack
}

// maxConcurrentPings bounds the number of ICMP echo requests being forwarded at
// once. Each forward holds a goroutine and a dedicated ICMP socket for up to the
// reply timeout, so without a limit a flood ping from the VM could exhaust file
// descriptors and goroutines on the host.
const maxConcurrentPings = 100

func ICMP(s *stack.Stack, nat map[tcpip.Address]tcpip.Address, natLock *sync.Mutex) *Forwarder {
	// Buffered channel used as a counting semaphore to cap in-flight pings.
	pingSem := make(chan struct{}, maxConcurrentPings)
	return NewForwarder(s, func(r *ICMPForwarderRequest) {
		pkt := r.Packet()
		if pkt == nil {
			log.Warningf("Dropping ICMP packet from VM (no packet data)")
			return
		}

		// HandlePacket transferred one reference on pkt to this request.
		// Release it on every path except when ownership is handed off to
		// the handlePingRequest goroutine (which DecRefs it when done).
		forwarded := false
		defer func() {
			if !forwarded {
				pkt.DecRef()
			}
		}()

		localAddress := r.ID().LocalAddress

		// Apply NAT translation if needed
		natLock.Lock()
		if replaced, ok := nat[localAddress]; ok {
			localAddress = replaced
		}
		natLock.Unlock()

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

		// This is a PING request - forward it using unprivileged ICMP sockets.
		// Bound concurrency so a flood ping cannot spawn unlimited goroutines
		// and sockets; drop the request when the limit is reached.
		select {
		case pingSem <- struct{}{}:
		default:
			log.Warningf("Dropping ICMP echo request from VM (too many in-flight pings)")
			return
		}
		go func() {
			defer func() { <-pingSem }()
			handlePingRequest(s, r, localAddress, icmpHeader, pkt)
		}()
		forwarded = true
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
