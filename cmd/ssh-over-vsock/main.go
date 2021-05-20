package main

import (
	"flag"
	"fmt"
	"net"

	"github.com/containers/gvisor-tap-vsock/pkg/transport"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var (
	ip       string
	port     int
	endpoint string
)

func main() {
	flag.StringVar(&ip, "ip", "192.168.127.2", "ip of the host")
	flag.IntVar(&port, "port", 22, "port of the host")
	flag.StringVar(&endpoint, "url", "/tmp/network.sock", "url of the daemon")
	flag.Parse()

	if err := run(); err != nil {
		logrus.Fatal(err)
	}
}

func run() error {
	conn, err := net.Dial("unix", endpoint)
	if err != nil {
		return errors.Wrap(err, "cannot connect to host")
	}
	defer conn.Close()

	if err := transport.Tunnel(conn, ip, port); err != nil {
		return err
	}

	client, err := newClient(conn, "core", "/home/guillaumerose/.crc/machines/crc/id_rsa")
	if err != nil {
		return err
	}
	out, err := client.output("ps")
	if err != nil {
		return err
	}
	fmt.Println(out)
	return nil
}
