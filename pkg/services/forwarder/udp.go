package forwarder

import (
	"net"
	"strconv"
	"sync"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
	log "github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

func UDP(s *stack.Stack, nat map[tcpip.Address]tcpip.Address, natLock *sync.Mutex, ec2MetadataAccess bool, policy *types.EgressPolicyHolder) *udp.Forwarder {
	return udp.NewForwarder(s, func(r *udp.ForwarderRequest) bool {
		localAddress := r.ID().LocalAddress

		if (!ec2MetadataAccess) && linkLocal().Contains(localAddress) || (localAddress == header.IPv4Broadcast) {
			return true
		}

		natLock.Lock()
		if replaced, ok := nat[localAddress]; ok {
			localAddress = replaced
		}
		natLock.Unlock()
		if !policy.Allows("udp", localAddress.String(), r.ID().LocalPort) {
			log.Debugf("egress policy denied udp %s:%d revision=%s", localAddress, r.ID().LocalPort, policy.Revision())
			return true
		}

		var wq waiter.Queue
		ep, tcpErr := r.CreateEndpoint(&wq)
		if tcpErr != nil {
			if _, ok := tcpErr.(*tcpip.ErrConnectionRefused); ok {
				// transient error
				log.Debugf("r.CreateEndpoint() = %v", tcpErr)
			} else {
				log.Errorf("r.CreateEndpoint() = %v", tcpErr)
			}
			return false
		}

		p, _ := NewUDPProxy(&autoStoppingListener{underlying: gonet.NewUDPConn(&wq, ep)}, func(_ net.Addr) (net.Conn, error) {
			return net.Dial("udp", net.JoinHostPort(localAddress.String(), strconv.Itoa(int(r.ID().LocalPort))))
		})
		flowID := policy.Track("udp", localAddress.String(), r.ID().LocalPort, p)
		if flowID == 0 && policy.Enabled() {
			_ = p.Close()
			return true
		}
		go func() {
			if flowID != 0 {
				defer policy.Untrack(flowID)
			}
			p.Run()

			// note that at this point packets that are sent to the current forwarder session
			// will be dropped. We will start processing the packets again when we get a new
			// forwarder request.
			ep.Close()
		}()
		return true
	})
}
