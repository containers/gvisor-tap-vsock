package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path"
	"runtime"

	log "github.com/golang/glog"
	"github.com/linuxkit/virtsock/pkg/hvsock"
	mdlayhervsock "github.com/mdlayher/vsock"
	"github.com/pkg/errors"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const (
	subnet     = "192.168.127.0"
	subnetMask = "255.255.255.0"

	gateway           = "192.168.127.1"
	gatewayMacAddress = "\x5A\x94\xEF\xE4\x0C\xDD"

	vm = "192.168.127.0"
)

var (
	debug bool
	mtu   int
)

func main() {
	flag.BoolVar(&debug, "debug", false, "debug")
	flag.IntVar(&mtu, "mtu", 1500, "mtu")
	flag.Parse()

	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ln, err := listen()
	if err != nil {
		return errors.Wrap(err, "cannot listen vsock")
	}

	endpoint := &TapLinkEndpoint{
		Listener:            ln,
		Debug:               debug,
		MaxTransmissionUnit: mtu,
		Mac:                 tcpip.LinkAddress(gatewayMacAddress),
	}

	stack, err := createStack(endpoint)
	if err != nil {
		return errors.Wrap(err, "cannot create network stack")
	}

	if err := addServices(stack); err != nil {
		return errors.Wrap(err, "cannot add network services")
	}

	// stack.Wait()
	return endpoint.AcceptOne()
}

func createStack(endpoint stack.LinkEndpoint) (*stack.Stack, error) {
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

	if err := s.AddAddress(1, ipv4.ProtocolNumber, tcpip.Address(net.ParseIP(gateway).To4())); err != nil {
		return nil, errors.New(err.String())
	}

	s.SetPromiscuousMode(1, true)

	subnet, err := tcpip.NewSubnet(tcpip.Address(net.ParseIP(subnet).To4()), tcpip.AddressMask(net.ParseIP(subnetMask).To4()))
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

func listen() (net.Listener, error) {
	// TODO: use less error-prone flags to detect OS
	if runtime.GOOS == "windows" {
		svcid, err := hvsock.GUIDFromString(fmt.Sprintf("%08x-FACB-11E6-BD58-64006A7986D3", 1024))
		if err != nil {
			return nil, err
		}
		return hvsock.Listen(hvsock.Addr{
			VMID:      hvsock.GUIDWildcard,
			ServiceID: svcid,
		})
	}
	if runtime.GOOS == "darwin" {
		path := path.Join(os.Getenv("VM_DIRECTORY"), fmt.Sprintf("00000002.%08x", 1024))
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		return net.ListenUnix("unix", &net.UnixAddr{
			Name: path,
			Net:  "unix",
		})

	}
	return mdlayhervsock.Listen(1024)
}
