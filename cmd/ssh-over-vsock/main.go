package main

import (
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/containers/gvisor-tap-vsock/pkg/transport"
	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var (
	ip       string
	port     int
	user     string
	key      string
	endpoint string
)

func main() {
	version := types.NewVersion("ssh-over-vsock")
	version.AddFlag()
	flag.StringVar(&ip, "ip", "192.168.127.2", "ip of the host")
	flag.IntVar(&port, "port", 22, "port of the host")
	flag.StringVar(&user, "user", "", "ssh user")
	flag.StringVar(&key, "key", "", "ssh key")
	flag.StringVar(&endpoint, "url", "/tmp/network.sock", "url of the daemon")
	flag.Parse()

	if version.ShowVersion() {
		fmt.Println(version.String())
		os.Exit(0)
	}

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

	client, err := newClient(conn, user, key)
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
