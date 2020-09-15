package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/code-ready/gvisor-tap-vsock/pkg/transport"
	"github.com/code-ready/gvisor-tap-vsock/pkg/types"
	"github.com/code-ready/gvisor-tap-vsock/pkg/virtualnetwork"
	"github.com/dustin/go-humanize"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

var (
	debug     bool
	mtu       int
	endpoints arrayFlags
)

func main() {
	flag.Var(&endpoints, "listen", fmt.Sprintf("url where the tap send packets (default %s)", transport.DefaultURL))
	flag.BoolVar(&debug, "debug", false, "debug")
	flag.IntVar(&mtu, "mtu", 1500, "mtu")
	flag.Parse()

	if len(endpoints) == 0 {
		endpoints = append(endpoints, transport.DefaultURL)
	}

	if err := run(&types.Configuration{
		Debug:             debug,
		CaptureFile:       captureFile(),
		MTU:               mtu,
		Subnet:            "192.168.127.0/24",
		GatewayIP:         "192.168.127.1",
		GatewayMacAddress: "\x5A\x94\xEF\xE4\x0C\xDD",
		DNSRecords: map[string]net.IP{
			"gateway.crc.testing.":            net.ParseIP("192.168.127.1"),
			"apps-crc.testing.":               net.ParseIP("192.168.130.11"),
			"etcd-0.crc.testing.":             net.ParseIP("192.168.130.11"),
			"api.crc.testing.":                net.ParseIP("192.168.130.11"),
			"crc-zqfk6-master-0.crc.testing.": net.ParseIP("192.168.126.11"),
		},
		Forwards: map[string]string{
			":2222": "192.168.127.2:22",
		},
	}, endpoints); err != nil {
		log.Fatal(err)
	}
}

type arrayFlags []string

func (i *arrayFlags) String() string {
	return "my string representation"
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func captureFile() string {
	if !debug {
		return ""
	}
	return "capture.pcap"
}

func run(configuration *types.Configuration, endpoints []string) error {
	vn, err := virtualnetwork.New(configuration)
	if err != nil {
		return err
	}
	log.Info("waiting for clients...")
	errCh := make(chan error)

	for _, endpoint := range endpoints {
		log.Infof("listening %s", endpoint)
		ln, err := transport.Listen(endpoint)
		if err != nil {
			return errors.Wrap(err, "cannot listen")
		}

		go func() {
			if err := http.Serve(ln, vn.Mux()); err != nil {
				errCh <- err
			}
		}()
	}
	go func() {
		for {
			fmt.Printf("%v sent to the VM, %v received from the VM\n", humanize.Bytes(vn.BytesSent()), humanize.Bytes(vn.BytesReceived()))
			time.Sleep(5 * time.Second)
		}
	}()
	return <-errCh
}
