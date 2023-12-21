package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/transport"
	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/songgao/packets/ethernet"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

var (
	endpoint         string
	iface            string
	stopIfIfaceExist string
	mac              string
	debug            bool
	mtu              int
	tapPreexists     bool
)

func main() {
	version := types.NewVersion("gvforwarder")
	version.AddFlag()
	flag.StringVar(&endpoint, "url", fmt.Sprintf("vsock://2:1024%s", types.ConnectPath), "url where the tap send packets")
	flag.StringVar(&iface, "iface", "tap0", "tap interface name")
	flag.StringVar(&stopIfIfaceExist, "stop-if-exist", "eth0,ens3,enp0s1", "stop if one of these interfaces exists at startup")
	flag.StringVar(&mac, "mac", "5a:94:ef:e4:0c:ee", "mac address")
	flag.BoolVar(&debug, "debug", false, "debug")
	flag.IntVar(&mtu, "mtu", 4000, "mtu")
	flag.BoolVar(&tapPreexists, "preexisting", false, "use preexisting/preconfigured TAP interface")
	flag.Parse()

	if version.ShowVersion() {
		fmt.Println(version.String())
		os.Exit(0)
	}

	expected := strings.Split(stopIfIfaceExist, ",")
	links, err := netlink.LinkList()
	if err != nil {
		log.Fatal(err)
	}
	for _, link := range links {
		if contains(expected, link.Attrs().Name) {
			log.Infof("interface %s prevented this program to run", link.Attrs().Name)
			return
		}
	}
	for {
		if err := run(); err != nil {
			log.Error(err)
		}
		time.Sleep(time.Second)
	}
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func run() error {
	conn, path, err := transport.Dial(endpoint)
	if err != nil {
		return errors.Wrap(err, "cannot connect to host")
	}
	defer conn.Close()

	if path != "" {
		req, err := http.NewRequest("POST", path, nil)
		if err != nil {
			return err
		}
		if err := req.Write(conn); err != nil {
			return err
		}
	}

	tap, err := water.New(water.Config{
		DeviceType: water.TAP,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: iface,
		},
	})
	if err != nil {
		return errors.Wrap(err, "cannot create tap device")
	}
	defer tap.Close()

	if !tapPreexists {
		if err := linkUp(); err != nil {
			return errors.Wrap(err, "cannot set mac address")
		}
	}

	errCh := make(chan error, 1)
	go tx(conn, tap, errCh, mtu)
	go rx(conn, tap, errCh, mtu)
	if !tapPreexists {
		go func() {
			if err := dhcp(); err != nil {
				errCh <- errors.Wrap(err, "dhcp error")
			}
		}()
	}
	return <-errCh
}

func linkUp() error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}
	if mac == "" {
		return netlink.LinkSetUp(link)
	}
	hw, err := net.ParseMAC(mac)
	if err != nil {
		return err
	}
	if err := netlink.LinkSetHardwareAddr(link, hw); err != nil {
		return err
	}
	return netlink.LinkSetUp(link)
}

func dhcp() error {
	if _, err := exec.LookPath("udhcpc"); err == nil { // busybox dhcp client
		cmd := exec.Command("udhcpc", "-f", "-q", "-i", iface, "-v")
		cmd.Stderr = os.Stderr
		cmd.Stdout = os.Stdout
		return cmd.Run()
	}
	cmd := exec.Command("dhclient", "-4", "-d", "-v", iface)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	return cmd.Run()
}

func rx(conn net.Conn, tap *water.Interface, errCh chan error, mtu int) {
	log.Info("waiting for packets...")
	size := make([]byte, 2)
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

		binary.LittleEndian.PutUint16(size, uint16(n))
		if _, err := conn.Write(append(size, frame...)); err != nil {
			errCh <- errors.Wrap(err, "cannot write size and packet to socket")
			return
		}
	}
}

func tx(conn net.Conn, tap *water.Interface, errCh chan error, mtu int) {
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
