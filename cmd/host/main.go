package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/code-ready/gvisor-tap-vsock/pkg/transport"
	"github.com/code-ready/gvisor-tap-vsock/pkg/types"
	"github.com/code-ready/gvisor-tap-vsock/pkg/virtualnetwork"
	"github.com/dustin/go-humanize"
	log "github.com/sirupsen/logrus"
)

var (
	endpoint string
	debug    bool
	mtu      int
)

func main() {
	flag.StringVar(&endpoint, "url", transport.DefaultURL, "url where the tap send packets")
	flag.BoolVar(&debug, "debug", false, "debug")
	flag.IntVar(&mtu, "mtu", 1500, "mtu")
	flag.Parse()

	if err := run(&types.Configuration{
		Debug:             debug,
		CaptureFile:       "capture.pcap",
		Endpoint:          endpoint,
		MTU:               mtu,
		Subnet:            "192.168.127.0",
		SubnetMask:        "255.255.255.0",
		GatewayIP:         "192.168.127.1",
		GatewayMacAddress: "\x5A\x94\xEF\xE4\x0C\xDD",
		VMIP:              "192.168.127.2",
	}); err != nil {
		log.Fatal(err)
	}
}

func run(configuration *types.Configuration) error {
	vn, err := virtualnetwork.New(configuration)
	if err != nil {
		return err
	}
	go func() {
		for {
			fmt.Printf("%v sent to the VM, %v received from the VM\n", humanize.Bytes(vn.BytesSent()), humanize.Bytes(vn.BytesReceived()))
			time.Sleep(5 * time.Second)
		}
	}()
	return vn.Run()
}
