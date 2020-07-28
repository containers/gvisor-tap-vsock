package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"

	log "github.com/golang/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	linuxkitvsock "github.com/linuxkit/virtsock/pkg/vsock"
	mdlayhervsock "github.com/mdlayher/vsock"
	"github.com/pkg/errors"
	"github.com/songgao/packets/ethernet"
	"github.com/songgao/water"
)

var (
	windows bool
	debug   bool
)

func main() {
	flag.BoolVar(&windows, "windows", false, "windows")
	flag.BoolVar(&debug, "debug", false, "debug")
	flag.Parse()

	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	conn, err := dial()
	if err != nil {
		return errors.Wrap(err, "cannot connect to host")
	}
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

	errCh := make(chan error, 1)
	go tx(conn, tap, errCh)
	go rx(conn, tap, errCh)
	return <-errCh
}

func dial() (net.Conn, error) {
	if windows {
		return linuxkitvsock.Dial(linuxkitvsock.CIDHost, uint32(1024))
	}
	return mdlayhervsock.Dial(2, 1024)
}

func rx(conn net.Conn, tap *water.Interface, errCh chan error) {
	log.Info("waiting for packets...")
	var frame ethernet.Frame
	for {
		frame.Resize(1500)
		n, err := tap.Read([]byte(frame))
		if err != nil {
			errCh <- errors.Wrap(err, "cannot read packet from tap")
			return
		}
		frame = frame[:n]

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
	for {
		sizeBuf := make([]byte, 2)
		n, err := conn.Read(sizeBuf)
		if err != nil {
			errCh <- errors.Wrap(err, "cannot read size from socket")
			return
		}
		if n != 2 {
			errCh <- fmt.Errorf("unexpected size %d", n)
			return
		}
		size := int(binary.LittleEndian.Uint16(sizeBuf[0:2]))

		buf := make([]byte, size)
		n, err = conn.Read(buf)
		if err != nil {
			errCh <- errors.Wrap(err, "cannot read payload from socket")
			return
		}
		if n == 0 {
			errCh <- fmt.Errorf("unexpected size %d != %d", n, size)
			return
		}

		if debug {
			packet := gopacket.NewPacket(buf, layers.LayerTypeEthernet, gopacket.Default)
			log.Info(packet.String())
		}

		if _, err := tap.Write(buf); err != nil {
			errCh <- errors.Wrap(err, "cannot write packet to tap")
			return
		}
	}
}
