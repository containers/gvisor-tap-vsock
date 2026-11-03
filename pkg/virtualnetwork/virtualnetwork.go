package virtualnetwork

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/containers/gvisor-tap-vsock/pkg/notification"
	"github.com/containers/gvisor-tap-vsock/pkg/services/forwarder"
	"github.com/containers/gvisor-tap-vsock/pkg/tap"
	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

type VirtualNetwork struct {
	configuration      *types.Configuration
	stack              *stack.Stack
	networkSwitch      *tap.Switch
	servicesMux        http.Handler
	ipPool             *tap.IPPool
	portsForwarder     *forwarder.PortsForwarder
	egressPolicy       *types.EgressPolicyHolder
	apiToken           string // Bearer token for API authentication
	egressPolicyLoader func() (*types.EgressPolicy, error)
}

func (n *VirtualNetwork) SetNotificationSender(notificationSender *notification.NotificationSender) {
	n.networkSwitch.SetNotificationSender(notificationSender)
}

func (n *VirtualNetwork) SetAPIToken(token string) {
	n.apiToken = token
}

// SetEgressPolicyLoader configures the trusted source used by the reload API.
// The loader is called only after the request passes the services API auth.
func (n *VirtualNetwork) SetEgressPolicyLoader(loader func() (*types.EgressPolicy, error)) {
	n.egressPolicyLoader = loader
}

func New(configuration *types.Configuration, requireEgressPolicy ...bool) (*VirtualNetwork, error) {
	var endpoint stack.LinkEndpoint

	required := false
	if len(requireEgressPolicy) > 0 {
		required = requireEgressPolicy[0]
	}
	egressPolicy, err := types.NewEgressPolicyHolder(configuration.EgressPolicy, required)
	if err != nil {
		return nil, fmt.Errorf("invalid egress policy: %w", err)
	}

	ipPool, err := tap.NewIPPool(configuration.Subnet)
	if err != nil {
		return nil, fmt.Errorf("cannot parse subnet CIDR: %w", err)
	}
	if err := ipPool.Reserve(configuration.GatewayIP, configuration.GatewayMacAddress); err != nil {
		return nil, fmt.Errorf("cannot reserve gateway IP: %w", err)
	}
	for ip, mac := range configuration.DHCPStaticLeases {
		if err := ipPool.Reserve(ip, mac); err != nil {
			return nil, fmt.Errorf("cannot reserve static lease IP %s: %w", ip, err)
		}
	}

	mtu := configuration.MTU
	if mtu < 0 || mtu > math.MaxInt32 {
		return nil, errors.New("mtu is out of range")
	}
	tapEndpoint, err := tap.NewLinkEndpoint(configuration.Debug, uint32(mtu), configuration.GatewayMacAddress, configuration.GatewayIP, configuration.GatewayVirtualIPs)
	if err != nil {
		return nil, fmt.Errorf("cannot create tap endpoint: %w", err)
	}
	networkSwitch := tap.NewSwitch(configuration.Debug)
	tapEndpoint.Connect(networkSwitch)
	networkSwitch.Connect(tapEndpoint)

	if configuration.CaptureFile != "" {
		_ = os.Remove(configuration.CaptureFile)
		fd, err := os.Create(configuration.CaptureFile)
		if err != nil {
			return nil, fmt.Errorf("cannot create capture file: %w", err)
		}
		endpoint, err = sniffer.NewWithWriter(tapEndpoint, fd, math.MaxUint32)
		if err != nil {
			return nil, fmt.Errorf("cannot create sniffer: %w", err)
		}
	} else {
		endpoint = tapEndpoint
	}
	stack, err := createStack(configuration, endpoint)
	if err != nil {
		return nil, fmt.Errorf("cannot create network stack: %w", err)
	}

	portsForwarder, err := createPortsForwarder(configuration, stack)
	if err != nil {
		return nil, fmt.Errorf("cannot create ports forwarder: %w", err)
	}
	mux, err := addServices(configuration, stack, ipPool, portsForwarder, egressPolicy)
	if err != nil {
		return nil, fmt.Errorf("cannot add network services: %w", err)
	}

	return &VirtualNetwork{
		configuration:  configuration,
		stack:          stack,
		networkSwitch:  networkSwitch,
		servicesMux:    mux,
		ipPool:         ipPool,
		portsForwarder: portsForwarder,
		egressPolicy:   egressPolicy,
	}, nil
}

func (n *VirtualNetwork) Close() error {
	err := n.portsForwarder.Close()
	if policyErr := n.egressPolicy.Close(); err == nil {
		err = policyErr
	}
	return err
}

// UpdateEgressPolicy atomically replaces the active policy and closes tracked
// outbound flows that the new policy denies.
func (n *VirtualNetwork) UpdateEgressPolicy(policy *types.EgressPolicy) error {
	return n.egressPolicy.Update(policy)
}

// ReloadEgressPolicy loads and atomically installs the policy from the
// configured trusted source. A loader or validation failure keeps the current
// policy active.
func (n *VirtualNetwork) ReloadEgressPolicy() error {
	if n.egressPolicyLoader == nil {
		return errors.New("egress policy reload is unavailable")
	}
	policy, err := n.egressPolicyLoader()
	if err != nil {
		return err
	}
	return n.UpdateEgressPolicy(policy)
}

// EgressPolicyRevision returns the active policy revision.
func (n *VirtualNetwork) EgressPolicyRevision() string {
	return n.egressPolicy.Revision()
}

func (n *VirtualNetwork) BytesSent() uint64 {
	if n.networkSwitch == nil {
		return 0
	}
	return n.networkSwitch.Sent
}

func (n *VirtualNetwork) BytesReceived() uint64 {
	if n.networkSwitch == nil {
		return 0
	}
	return n.networkSwitch.Received
}

func createStack(configuration *types.Configuration, endpoint stack.LinkEndpoint) (*stack.Stack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			arp.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
		},
	})

	if err := s.CreateNIC(1, endpoint); err != nil {
		return nil, errors.New(err.String())
	}

	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4Slice(net.ParseIP(configuration.GatewayIP).To4()).WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		return nil, errors.New(err.String())
	}

	s.SetSpoofing(1, true)
	s.SetPromiscuousMode(1, true)

	_, parsedSubnet, err := net.ParseCIDR(configuration.Subnet)
	if err != nil {
		return nil, fmt.Errorf("cannot parse cidr: %w", err)
	}

	subnet, err := tcpip.NewSubnet(tcpip.AddrFromSlice(parsedSubnet.IP), tcpip.MaskFromBytes(parsedSubnet.Mask))
	if err != nil {
		return nil, fmt.Errorf("cannot parse subnet: %w", err)
	}
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: subnet,
			Gateway:     tcpip.Address{},
			NIC:         1,
		},
	})

	return s, nil
}

func createPortsForwarder(configuration *types.Configuration, s *stack.Stack) (*forwarder.PortsForwarder, error) {
	fw := forwarder.NewPortsForwarder(s)
	for local, remote := range configuration.Forwards {
		if strings.HasPrefix(local, "udp:") {
			if err := fw.Expose(types.UDP, strings.TrimPrefix(local, "udp:"), remote); err != nil {
				return nil, err
			}
		} else {
			if err := fw.Expose(types.TCP, local, remote); err != nil {
				return nil, err
			}
		}
	}
	return fw, nil
}
