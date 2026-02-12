package forwarder

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"regexp"
	"sync"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/tcpproxy"
	log "github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const linkLocalSubnet = "169.254.0.0/16"

type tcpAction int

const (
	tcpBlock tcpAction = iota
	tcpDirect
	tcpTLSAllowlist
)

// tcpRoutingAction decides what to do with an inbound TCP connection based on
// the destination address, port, and active filtering configuration.
func tcpRoutingAction(
	localAddress tcpip.Address,
	localPort uint16,
	blockAllOutbound bool,
	allowlistActive bool,
	gatewayAddr tcpip.Address,
) tcpAction {
	if blockAllOutbound {
		return tcpBlock
	}
	if allowlistActive {
		if localAddress == gatewayAddr {
			return tcpDirect
		}
		if localPort == 443 {
			return tcpTLSAllowlist
		}
		return tcpBlock
	}
	return tcpDirect
}

func TCP(s *stack.Stack, nat map[tcpip.Address]tcpip.Address, natLock *sync.Mutex, ec2MetadataAccess bool, blockAllOutbound bool, outboundAllow []*regexp.Regexp, gatewayIP net.IP) *tcp.Forwarder {
	allowlistActive := len(outboundAllow) > 0
	var gatewayAddr tcpip.Address
	if gatewayIP != nil {
		gatewayAddr = tcpip.AddrFrom4Slice(gatewayIP.To4())
	}

	return tcp.NewForwarder(s, 0, 10, func(r *tcp.ForwarderRequest) {
		localAddress := r.ID().LocalAddress
		action := tcpRoutingAction(localAddress, r.ID().LocalPort,
			blockAllOutbound, allowlistActive, gatewayAddr)
		switch action {
		case tcpBlock:
			if blockAllOutbound {
				log.Debugf("Blocking outbound TCP to %s:%d (blockAllOutbound=true)",
					localAddress.String(), r.ID().LocalPort)
			} else {
				log.Debugf("Blocking outbound TCP to %s:%d (outboundAllow active, non-443 port)",
					localAddress.String(), r.ID().LocalPort)
			}
			r.Complete(true)
		case tcpTLSAllowlist:
			handleTLSWithAllowlist(r, nat, natLock, localAddress, outboundAllow)
		case tcpDirect:
			handleDirectTCP(r, nat, natLock, localAddress, ec2MetadataAccess)
		}
	})
}

// handleDirectTCP is the original forwarding path: dial outbound, then proxy.
func handleDirectTCP(r *tcp.ForwarderRequest, nat map[tcpip.Address]tcpip.Address, natLock *sync.Mutex, localAddress tcpip.Address, ec2MetadataAccess bool) {
	if (!ec2MetadataAccess) && linkLocal().Contains(localAddress) {
		r.Complete(true)
		return
	}

	natLock.Lock()
	if replaced, ok := nat[localAddress]; ok {
		localAddress = replaced
	}
	natLock.Unlock()
	outbound, err := net.Dial("tcp", net.JoinHostPort(localAddress.String(), fmt.Sprint(r.ID().LocalPort)))
	if err != nil {
		log.Tracef("net.Dial() = %v", err)
		r.Complete(true)
		return
	}

	var wq waiter.Queue
	ep, tcpErr := r.CreateEndpoint(&wq)
	r.Complete(false)
	if tcpErr != nil {
		outbound.Close()
		if _, ok := tcpErr.(*tcpip.ErrConnectionRefused); ok {
			log.Debugf("r.CreateEndpoint() = %v", tcpErr)
		} else {
			log.Errorf("r.CreateEndpoint() = %v", tcpErr)
		}
		return
	}

	remote := tcpproxy.DialProxy{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return outbound, nil
		},
	}
	remote.HandleConn(gonet.NewTCPConn(&wq, ep))
}

// handleTLSWithAllowlist accepts the guest TCP connection, peeks at the TLS
// ClientHello to extract the SNI, checks it against the allowlist, and only
// then dials the outbound connection. Peeked bytes are replayed via
// tcpproxy.Conn so the remote server sees the full ClientHello.
func handleTLSWithAllowlist(r *tcp.ForwarderRequest, nat map[tcpip.Address]tcpip.Address, natLock *sync.Mutex, localAddress tcpip.Address, outboundAllow []*regexp.Regexp) {
	// Accept the guest TCP connection (complete the 3-way handshake).
	var wq waiter.Queue
	ep, tcpErr := r.CreateEndpoint(&wq)
	r.Complete(false)
	if tcpErr != nil {
		if _, ok := tcpErr.(*tcpip.ErrConnectionRefused); ok {
			log.Debugf("r.CreateEndpoint() = %v", tcpErr)
		} else {
			log.Errorf("r.CreateEndpoint() = %v", tcpErr)
		}
		return
	}

	guestConn := gonet.NewTCPConn(&wq, ep)

	// Set a read deadline for the ClientHello.
	if err := guestConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		log.Debugf("SetReadDeadline() = %v", err)
		guestConn.Close()
		return
	}

	// Buffer must be large enough to hold a multi-fragment ClientHello.
	// A maxClientHelloLen (65536) body + 4-byte handshake header = 65540
	// payload bytes, spanning up to 5 TLS records (each <=16384 payload
	// + 5-byte header). Total: 65540 + 5*5 headers = 65565 bytes.
	br := bufio.NewReaderSize(guestConn, maxClientHelloLen+5*5+4)
	sni, _, err := PeekSNI(br)

	// Reset read deadline.
	_ = guestConn.SetReadDeadline(time.Time{})

	if err != nil {
		log.Debugf("Blocking TLS to %s: SNI parse error: %v", localAddress.String(), err)
		guestConn.Close()
		return
	}

	if !MatchesAllowlist(sni, outboundAllow) {
		log.Debugf("Blocking TLS to %s: SNI %q not in allowlist", localAddress.String(), sni)
		guestConn.Close()
		return
	}

	log.Debugf("Allowing TLS to %s: SNI %q matches allowlist", localAddress.String(), sni)

	// NAT translation.
	natLock.Lock()
	if replaced, ok := nat[localAddress]; ok {
		localAddress = replaced
	}
	natLock.Unlock()

	// Dial outbound only after allowlist passes.
	outbound, err := net.Dial("tcp", net.JoinHostPort(localAddress.String(), "443"))
	if err != nil {
		log.Tracef("net.Dial() = %v", err)
		guestConn.Close()
		return
	}

	// Wrap the guest connection to replay peeked bytes.
	peeked, _ := br.Peek(br.Buffered())
	peekedCopy := make([]byte, len(peeked))
	copy(peekedCopy, peeked)

	wrappedConn := &tcpproxy.Conn{
		Peeked: peekedCopy,
		Conn:   guestConn,
	}

	remote := tcpproxy.DialProxy{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return outbound, nil
		},
	}
	remote.HandleConn(wrappedConn)
}

func linkLocal() *tcpip.Subnet {
	_, parsedSubnet, _ := net.ParseCIDR(linkLocalSubnet) // CoreOS VM tries to connect to Amazon EC2 metadata service
	subnet, _ := tcpip.NewSubnet(tcpip.AddrFromSlice(parsedSubnet.IP), tcpip.MaskFromBytes(parsedSubnet.Mask))
	return &subnet
}
