package main

import (
	"flag"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"time"

	log "github.com/golang/glog"
	"github.com/linuxkit/virtsock/pkg/hvsock"
	mdlayhervsock "github.com/mdlayher/vsock"
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

const (
	subnet     = "192.168.127.0"
	subnetMask = "255.255.255.0"

	gateway           = "192.168.127.1"
	gatewayMacAddress = "\x5A\x94\xEF\xE4\x0C\xDD"

	vm = "192.168.127.2"
)

var (
	debug bool
	mtu   int
)

func main() {
	flag.BoolVar(&debug, "debug", false, "debug")
	flag.IntVar(&mtu, "mtu", 1500, "mtu")
	flag.Parse()

	if err := run(debug, mtu); err != nil {
		log.Fatal(err)
	}
}

func run(debug bool, mtu int) error {
	conn, err := dial()
	if err != nil {
		return errors.Wrap(err, "cannot listen vsock")
	}

	var endpoint stack.LinkEndpoint
	tapEndpoint := &TapLinkEndpoint{
		Conn:                conn,
		Debug:               debug,
		MaxTransmissionUnit: mtu,
		Mac:                 tcpip.LinkAddress(gatewayMacAddress),
	}
	if debug {
		_ = os.Remove("capture.pcap")
		fd, err := os.Create("capture.pcap")
		if err != nil {
			return errors.Wrap(err, "cannot create capture file")
		}
		endpoint, err = sniffer.NewWithWriter(tapEndpoint, fd, math.MaxUint32)
		if err != nil {
			return errors.Wrap(err, "cannot create sniffer")
		}
	} else {
		endpoint = tapEndpoint
	}

	stack, err := createStack(endpoint)
	if err != nil {
		return errors.Wrap(err, "cannot create network stack")
	}

	if err := addServices(stack); err != nil {
		return errors.Wrap(err, "cannot add network services")
	}

	// stack.Wait()

	go func() {
		for {
			fmt.Printf("%v packets sent, %v packets received\n", stack.Stats().IP.PacketsSent.Value(), stack.Stats().IP.PacketsReceived.Value())
			time.Sleep(5 * time.Second)
		}

	}()
	return tapEndpoint.AcceptOne()
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

func dial() (net.Conn, error) {
	if runtime.GOOS == "windows" {
		svcid, err := hvsock.GUIDFromString(fmt.Sprintf("%08x-FACB-11E6-BD58-64006A7986D3", 1024))
		if err != nil {
			return nil, err
		}
		vmid, err := hvsock.GUIDFromString(os.Getenv("VMID"))
		if err != nil {
			return nil, err
		}
		return hvsock.Dial(hvsock.Addr{
			VMID:      vmid,
			ServiceID: svcid,
		})
	}
	if runtime.GOOS == "darwin" {
		conn, err := net.Dial("unix", filepath.Join(os.Getenv("VM_DIRECTORY"), "connect"))
		if err != nil {
			return nil, err
		}
		if _, err := fmt.Fprintf(conn, "%08x.%08x\n", 3, 1024); err != nil {
			return nil, err
		}
		return conn, err
	}
	return mdlayhervsock.Dial(3, 1024)
}
