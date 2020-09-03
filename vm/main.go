package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os/exec"
	"os/user"

	log "github.com/golang/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	mdlayhervsock "github.com/mdlayher/vsock"
	"github.com/pkg/errors"
	"github.com/songgao/packets/ethernet"
	"github.com/songgao/water"
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

	user, err := user.Current()
	if err != nil {
		return err
	}
	commands := []string{
		"ip addr add 192.168.127.2/24 dev O_O",
		"ip link set dev O_O up",
		"route del default gw 192.168.130.1",
		"route add default gw 192.168.127.1 dev O_O",
		"ifconfig O_O mtu 1500 up",
	}
	defer func() {
		command := exec.Command("sudo", "/bin/sh", "-c", "route add default gw 192.168.130.1 dev ens3")
		if user.Uid == "0" {
			command = exec.Command("/bin/sh", "-c", "route add default gw 192.168.130.1 dev ens3")
		}
		out, err := command.CombinedOutput()
		if err != nil {
			log.Error(err)
			return
		}
		log.Info(out)
	}()
	for _, command := range commands {
		log.Infof("Running %s", command)
		cmd := exec.Command("sudo", "/bin/sh", "-c", command)
		if user.Uid == "0" {
			cmd = exec.Command("/bin/sh", "-c", command)
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			log.Error(err)
			continue
		}
		if len(out) > 0 {
			log.Info(out)
		}
	}

	return <-errCh
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
