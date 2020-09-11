package virtualnetwork

import (
	"fmt"
	"math"
	"net"
	"os"

	"github.com/code-ready/gvisor-tap-vsock/pkg/tap"
	"github.com/code-ready/gvisor-tap-vsock/pkg/transport"
	"github.com/code-ready/gvisor-tap-vsock/pkg/types"
	"github.com/pkg/errors"
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
	configuration *types.Configuration
	stack         *stack.Stack
	tapEndpoint   *tap.LinkEndpoint
}

func New(configuration *types.Configuration) (*VirtualNetwork, error) {
	ln, err := transport.Listen(configuration.Endpoint)
	if err != nil {
		return nil, errors.Wrap(err, "cannot listen vsock")
	}

	var endpoint stack.LinkEndpoint
	tapEndpoint := &tap.LinkEndpoint{
		Listener:            ln,
		Debug:               configuration.Debug,
		MaxTransmissionUnit: configuration.MTU,
		Mac:                 tcpip.LinkAddress(configuration.GatewayMacAddress),
	}
	if configuration.CaptureFile != "" {
		_ = os.Remove(configuration.CaptureFile)
		fd, err := os.Create(configuration.CaptureFile)
		if err != nil {
			return nil, errors.Wrap(err, "cannot create capture file")
		}
		endpoint, err = sniffer.NewWithWriter(tapEndpoint, fd, math.MaxUint32)
		if err != nil {
			return nil, errors.Wrap(err, "cannot create sniffer")
		}
	} else {
		endpoint = tapEndpoint
	}

	stack, err := createStack(configuration, endpoint)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create network stack")
	}

	if err := addServices(configuration, stack); err != nil {
		return nil, errors.Wrap(err, "cannot add network services")
	}

	return &VirtualNetwork{
		configuration: configuration,
		stack:         stack,
		tapEndpoint:   tapEndpoint,
	}, nil
}

func (n *VirtualNetwork) BytesSent() uint64 {
	if n.tapEndpoint == nil {
		return 0
	}
	return n.tapEndpoint.Sent
}

func (n *VirtualNetwork) BytesReceived() uint64 {
	if n.tapEndpoint == nil {
		return 0
	}
	return n.tapEndpoint.Received
}

func (n *VirtualNetwork) Run() error {
	return n.tapEndpoint.AcceptOne(n.configuration.GatewayIP, fmt.Sprintf("%s/24", n.configuration.VMIP))
}

func createStack(configuration *types.Configuration, endpoint stack.LinkEndpoint) (*stack.Stack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{
			ipv4.NewProtocol(),
			arp.NewProtocol(),
		},
		TransportProtocols: []stack.TransportProtocol{
			tcp.NewProtocol(),
			udp.NewProtocol(),
			icmp.NewProtocol4(),
		},
	})

	if err := s.CreateNIC(1, endpoint); err != nil {
		return nil, errors.New(err.String())
	}

	if err := s.AddAddress(1, arp.ProtocolNumber, "arp"); err != nil {
		return nil, errors.New(err.String())
	}

	if err := s.AddAddress(1, ipv4.ProtocolNumber, tcpip.Address(net.ParseIP(configuration.GatewayIP).To4())); err != nil {
		return nil, errors.New(err.String())
	}

	s.SetPromiscuousMode(1, true)

	subnet, err := tcpip.NewSubnet(tcpip.Address(net.ParseIP(configuration.Subnet).To4()), tcpip.AddressMask(net.ParseIP(configuration.SubnetMask).To4()))
	if err != nil {
		return nil, err
	}
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: subnet,
			Gateway:     "",
			NIC:         1,
		},
	})

	return s, nil
}
