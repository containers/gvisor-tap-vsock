package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"regexp"
	"time"

	"github.com/code-ready/gvisor-tap-vsock/pkg/transport"
	"github.com/code-ready/gvisor-tap-vsock/pkg/types"
	"github.com/code-ready/gvisor-tap-vsock/pkg/virtualnetwork"
	"github.com/dustin/go-humanize"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

var (
	debug        bool
	mtu          int
	endpoints    arrayFlags
	vpnkitSocket string
)

func main() {
	flag.Var(&endpoints, "listen", fmt.Sprintf("url where the tap send packets (default %s)", transport.DefaultURL))
	flag.BoolVar(&debug, "debug", false, "debug")
	flag.IntVar(&mtu, "mtu", 1500, "mtu")
	flag.StringVar(&vpnkitSocket, "listen-vpnkit", "", "VPNKit socket to be used by Hyperkit")
	flag.Parse()

	if debug {
		log.SetLevel(log.DebugLevel)
	}

	if len(endpoints) == 0 {
		endpoints = append(endpoints, transport.DefaultURL)
	}

	if err := run(&types.Configuration{
		Debug:             debug,
		CaptureFile:       captureFile(),
		MTU:               mtu,
		Subnet:            "192.168.127.0/24",
		GatewayIP:         "192.168.127.1",
		GatewayMacAddress: "5a:94:ef:e4:0c:dd",
		DHCPStaticLeases: map[string]string{
			"192.168.127.2": "5a:94:ef:e4:0c:ee",
		},
		DNS: []types.Zone{
			{
				Name:      "apps-crc.testing.",
				DefaultIP: net.ParseIP("192.168.127.2"),
			},
			{
				Name: "crc.testing.",
				Records: []types.Record{
					{
						Name: "gateway",
						IP:   net.ParseIP("192.168.127.1"),
					},
					{
						Name: "host",
						IP:   net.ParseIP("192.168.127.254"),
					},
					{
						Name: "api",
						IP:   net.ParseIP("192.168.127.2"),
					},
					{
						Name: "api-int",
						IP:   net.ParseIP("192.168.127.2"),
					},
					{
						Regexp: regexp.MustCompile("crc-(.*?)-master-0"),
						IP:     net.ParseIP("192.168.126.11"),
					},
				},
			},
		},
		Forwards: map[string]string{
			":2222": "192.168.127.2:22",
		},
		NAT: map[string]string{
			"192.168.127.254": "127.0.0.1",
		},
		VpnKitUUIDMacAddresses: map[string]string{
			"c3d68012-0208-11ea-9fd7-f2189899ab08": "5a:94:ef:e4:0c:ee",
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

			if err := http.Serve(ln, withProfiler(vn)); err != nil {
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

	if vpnkitSocket != "" {
		vpnkitListener, err := transport.Listen(vpnkitSocket)
		if err != nil {
			return err
		}
		go func() {
			for {
				conn, err := vpnkitListener.Accept()
				if err != nil {
					log.Errorf("vpnkit accept error: %s", err)
					continue
				}
				go func() {
					if err := vn.AcceptVpnKit(conn); err != nil {
						log.Errorf("vpnkit error: %s", err)
					}
				}()
			}
		}()
	}

	ln, err := vn.Listen("tcp", fmt.Sprintf("%s:8080", configuration.GatewayIP))
	if err != nil {
		return err
	}
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
			_, _ = writer.Write([]byte(`Hello world!\n`))
		})
		if err := http.Serve(ln, mux); err != nil {
			errCh <- err
		}
	}()
	return <-errCh
}

func withProfiler(vn *virtualnetwork.VirtualNetwork) http.Handler {
	mux := vn.Mux()
	if debug {
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	}
	return mux
}
