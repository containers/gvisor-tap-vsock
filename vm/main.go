package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"

	log "github.com/golang/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	mdlayhervsock "github.com/mdlayher/vsock"
	"github.com/pkg/errors"
	"github.com/songgao/packets/ethernet"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

var (
	windows bool
	debug   bool
	mtu     int
)

func main() {
	flag.BoolVar(&windows, "windows", false, "windows")
	flag.BoolVar(&debug, "debug", false, "debug")
	flag.IntVar(&mtu, "mtu", 1500, "mtu")
	flag.Parse()

	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ln, err := mdlayhervsock.Listen(1024)
	if err != nil {
		return err
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Error(err)
			continue
		}
		if err := handle(conn); err != nil {
			log.Error(err)
			continue
		}
	}
}

func handle(conn net.Conn) error {
	defer conn.Close()

	tap, err := water.New(water.Config{
		DeviceType: water.TAP,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: "O_O",
		},
	})
	if err != nil {
		return errors.Wrap(err, "cannot create tap device")
	}
	defer tap.Close()

	errCh := make(chan error, 1)
	go tx(conn, tap, errCh)
	go rx(conn, tap, errCh)

	cleanup, err := linkUp()
	defer cleanup()
	if err != nil {
		return err
	}
	return <-errCh
}

func linkUp() (func(), error) {
	link, err := netlink.LinkByName("O_O")
	if err != nil {
		return func() {}, err
	}
	newDefaultRoute := netlink.Route{
		LinkIndex: link.Attrs().Index,
		Gw:        net.ParseIP("192.168.127.1"),
	}
	var defaultRoute *netlink.Route
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	for _, r := range routes {
		if r.Dst == nil {
			defaultRoute = &r
			break
		}
	}
	if defaultRoute == nil {
		return func() {}, errors.New("no default gateway found")
	}
	cleanup := func() {
		if err := netlink.RouteAdd(defaultRoute); err != nil {
			log.Errorf("cannot restore old default gateway: %v", err)
		}
		if err := netlink.RouteDel(&newDefaultRoute); err != nil {
			log.Errorf("cannot remove new default gateway: %v", err)
		}
	}
	addr, err := netlink.ParseAddr("192.168.127.2/24")
	if err != nil {
		return cleanup, err
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		return cleanup, errors.Wrap(err, "cannot add address")
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return cleanup, errors.Wrap(err, "cannot set link up")
	}
	if err := netlink.RouteDel(defaultRoute); err != nil {
		return cleanup, errors.Wrap(err, "cannot remove old default gateway")
	}
	if err := netlink.RouteAdd(&newDefaultRoute); err != nil {
		return cleanup, errors.Wrap(err, "cannot add new default gateway")
	}
	return cleanup, nil
}

func rx(conn net.Conn, tap *water.Interface, errCh chan error) {
	log.Info("waiting for packets...")
	var frame ethernet.Frame
	for {
		frame.Resize(mtu)
		n, err := tap.Read([]byte(frame))
		if err != nil {
			errCh <- errors.Wrap(err, "cannot read packet from tap")
			return
		}
		frame = frame[:n]

		if debug {
			packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
			log.Info(packet.String())
		}

		size := make([]byte, 2)
		binary.LittleEndian.PutUint16(size, uint16(n))

		if _, err := conn.Write(size); err != nil {
			errCh <- errors.Wrap(err, "cannot write size to socket")
			return
		}
		if _, err := conn.Write(frame); err != nil {
			errCh <- errors.Wrap(err, "cannot write packet to socket")
			return
		}
	}
}

func tx(conn net.Conn, tap *water.Interface, errCh chan error) {
	sizeBuf := make([]byte, 2)
	buf := make([]byte, mtu+header.EthernetMinimumSize)

	for {
		n, err := io.ReadFull(conn, sizeBuf)
		if err != nil {
			errCh <- errors.Wrap(err, "cannot read size from socket")
			return
		}
		if n != 2 {
			errCh <- fmt.Errorf("unexpected size %d", n)
			return
		}
		size := int(binary.LittleEndian.Uint16(sizeBuf[0:2]))

		n, err = io.ReadFull(conn, buf[:size])
		if err != nil {
			errCh <- errors.Wrap(err, "cannot read payload from socket")
			return
		}
		if n == 0 || n != size {
			errCh <- fmt.Errorf("unexpected size %d != %d", n, size)
			return
		}

		if debug {
			packet := gopacket.NewPacket(buf[:size], layers.LayerTypeEthernet, gopacket.Default)
			log.Info(packet.String())
		}

		if _, err := tap.Write(buf[:size]); err != nil {
			errCh <- errors.Wrap(err, "cannot write packet to tap")
			return
		}
	}
}
