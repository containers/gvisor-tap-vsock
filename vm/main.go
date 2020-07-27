package main

import (
	"encoding/binary"
	"flag"
	"net"

	log "github.com/golang/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/mdlayher/vsock"
	"github.com/songgao/packets/ethernet"
	"github.com/songgao/water"
)

var debug bool

func main() {
	flag.BoolVar(&debug, "debug", false, "debug")
	flag.Parse()

	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	con, err := vsock.Dial(2, 1024)
	if err != nil {
		return err
	}

	tap, err := water.New(water.Config{
		DeviceType: water.TAP,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: "O_O",
		},
	})
	if err != nil {
		return err
	}

	go tx(con, tap)
	return rx(con, tap)
}

func rx(conn net.Conn, tap *water.Interface) error {
	log.Info("waiting for packets...")
	var frame ethernet.Frame
	for {
		frame.Resize(1500)
		n, err := tap.Read([]byte(frame))
		if err != nil {
			return err
		}
		frame = frame[:n]

		size := make([]byte, 2)
		binary.LittleEndian.PutUint16(size, uint16(n))

		if _, err := conn.Write(size); err != nil {
			log.Error(err)
		}
		if _, err := conn.Write(frame); err != nil {
			log.Error(err)
		}
	}
}

func tx(conn net.Conn, tap *water.Interface) {
	for {
		sizeBuf := make([]byte, 2)
		n, err := conn.Read(sizeBuf)
		if err != nil {
			log.Error(err)
			continue
		}
		if n != 2 {
			log.Errorf("unexpected size %d", n)
			continue
		}
		size := int(binary.LittleEndian.Uint16(sizeBuf[0:2]))

		buf := make([]byte, size)
		n, err = conn.Read(buf)
		if err != nil {
			log.Error(err)
			continue
		}
		if n == 0 {
			log.Errorf("unexpected size %d != %d", n, size)
			continue
		}

		if debug {
			packet := gopacket.NewPacket(buf, layers.LayerTypeEthernet, gopacket.Default)
			log.Info(packet.String())
		}

		if _, err := tap.Write(buf); err != nil {
			log.Error(err)
		}
	}
}
