package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/net/stdio"
	"github.com/containers/gvisor-tap-vsock/pkg/sshclient"
	"github.com/containers/gvisor-tap-vsock/pkg/transport"
	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/containers/gvisor-tap-vsock/pkg/virtualnetwork"
	"github.com/containers/winquit/pkg/winquit"
	"github.com/dustin/go-humanize"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

var (
	debug           bool
	mtu             int
	endpoints       arrayFlags
	vpnkitSocket    string
	qemuSocket      string
	bessSocket      string
	stdioSocket     string
	vfkitSocket     string
	forwardSocket   arrayFlags
	forwardDest     arrayFlags
	forwardUser     arrayFlags
	forwardIdentify arrayFlags
	sshPort         int
	pidFile         string
	exitCode        int
	logFile         string
)

const (
	gatewayIP   = "192.168.127.1"
	sshHostPort = "192.168.127.2:22"
	hostIP      = "192.168.127.254"
	host        = "host"
	gateway     = "gateway"
)

func main() {
	version := types.NewVersion("gvproxy")
	version.AddFlag()
	flag.Var(&endpoints, "listen", "control endpoint")
	flag.BoolVar(&debug, "debug", false, "Print debug info")
	flag.IntVar(&mtu, "mtu", 1500, "Set the MTU")
	flag.IntVar(&sshPort, "ssh-port", 2222, "Port to access the guest virtual machine. Must be between 1024 and 65535")
	flag.StringVar(&vpnkitSocket, "listen-vpnkit", "", "VPNKit socket to be used by Hyperkit")
	flag.StringVar(&qemuSocket, "listen-qemu", "", "Socket to be used by Qemu")
	flag.StringVar(&bessSocket, "listen-bess", "", "unixpacket socket to be used by Bess-compatible applications")
	flag.StringVar(&stdioSocket, "listen-stdio", "", "accept stdio pipe")
	flag.StringVar(&vfkitSocket, "listen-vfkit", "", "unixgram socket to be used by vfkit-compatible applications")
	flag.Var(&forwardSocket, "forward-sock", "Forwards a unix socket to the guest virtual machine over SSH")
	flag.Var(&forwardDest, "forward-dest", "Forwards a unix socket to the guest virtual machine over SSH")
	flag.Var(&forwardUser, "forward-user", "SSH user to use for unix socket forward")
	flag.Var(&forwardIdentify, "forward-identity", "Path to SSH identity key for forwarding")
	flag.StringVar(&pidFile, "pid-file", "", "Generate a file with the PID in it")
	flag.StringVar(&logFile, "log-file", "", "Output log messages (logrus) to a given file path")
	flag.Parse()

	if version.ShowVersion() {
		fmt.Println(version.String())
		os.Exit(0)
	}

	// If the user provides a log-file, we re-direct log messages
	// from logrus to the file
	if logFile != "" {
		lf, err := os.Create(logFile)
		if err != nil {
			fmt.Printf("unable to open log file %s, exiting...\n", logFile)
			os.Exit(1)
		}
		defer func() {
			if err := lf.Close(); err != nil {
				fmt.Printf("unable to close log-file: %q\n", err)
			}
		}()
		log.SetOutput(lf)

		// If debug is set, lets seed the log file with some basic information
		// about the environment and how it was called
		log.Debugf("gvproxy version: %q", version.String())
		log.Debugf("os: %q arch: %q", runtime.GOOS, runtime.GOARCH)
		log.Debugf("command line: %q", os.Args)
	}

	log.Info(version.String())
	ctx, cancel := context.WithCancel(context.Background())
	// Make this the last defer statement in the stack
	defer os.Exit(exitCode)

	groupErrs, ctx := errgroup.WithContext(ctx)
	// Setup signal channel for catching user signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	if debug {
		log.SetLevel(log.DebugLevel)
	}

	// Intercept WM_QUIT/WM_CLOSE events if on Windows as SIGTERM (noop on other OSs)
	winquit.SimulateSigTermOnQuit(sigChan)

	// Make sure the qemu socket provided is valid syntax
	if len(qemuSocket) > 0 {
		uri, err := url.Parse(qemuSocket)
		if err != nil || uri == nil {
			exitWithError(errors.Wrapf(err, "invalid value for listen-qemu"))
		}
		if _, err := os.Stat(uri.Path); err == nil && uri.Scheme == "unix" {
			exitWithError(errors.Errorf("%q already exists", uri.Path))
		}
	}
	if len(bessSocket) > 0 {
		uri, err := url.Parse(bessSocket)
		if err != nil || uri == nil {
			exitWithError(errors.Wrapf(err, "invalid value for listen-bess"))
		}
		if uri.Scheme != "unixpacket" {
			exitWithError(errors.New("listen-bess must be unixpacket:// address"))
		}
		if _, err := os.Stat(uri.Path); err == nil {
			exitWithError(errors.Errorf("%q already exists", uri.Path))
		}
	}
	if len(vfkitSocket) > 0 {
		uri, err := url.Parse(vfkitSocket)
		if err != nil || uri == nil {
			exitWithError(errors.Wrapf(err, "invalid value for listen-vfkit"))
		}
		if uri.Scheme != "unixgram" {
			exitWithError(errors.New("listen-vfkit must be unixgram:// address"))
		}
		if _, err := os.Stat(uri.Path); err == nil {
			exitWithError(errors.Errorf("%q already exists", uri.Path))
		}
	}

	if vpnkitSocket != "" && qemuSocket != "" {
		exitWithError(errors.New("cannot use qemu and vpnkit protocol at the same time"))
	}
	if vpnkitSocket != "" && bessSocket != "" {
		exitWithError(errors.New("cannot use bess and vpnkit protocol at the same time"))
	}
	if qemuSocket != "" && bessSocket != "" {
		exitWithError(errors.New("cannot use qemu and bess protocol at the same time"))
	}

	// If the given port is not between the privileged ports
	// and the oft considered maximum port, return an error.
	if sshPort != -1 && sshPort < 1024 || sshPort > 65535 {
		exitWithError(errors.New("ssh-port value must be between 1024 and 65535"))
	}
	protocol := types.HyperKitProtocol
	if qemuSocket != "" {
		protocol = types.QemuProtocol
	}
	if bessSocket != "" {
		protocol = types.BessProtocol
	}
	if vfkitSocket != "" {
		protocol = types.VfkitProtocol
	}

	if c := len(forwardSocket); c != len(forwardDest) || c != len(forwardUser) || c != len(forwardIdentify) {
		exitWithError(errors.New("-forward-sock, --forward-dest, --forward-user, and --forward-identity must all be specified together, " +
			"the same number of times, or not at all"))
	}

	for i := 0; i < len(forwardSocket); i++ {
		_, err := os.Stat(forwardIdentify[i])
		if err != nil {
			exitWithError(errors.Wrapf(err, "Identity file %s can't be loaded", forwardIdentify[i]))
		}
	}

	// Create a PID file if requested
	if len(pidFile) > 0 {
		f, err := os.Create(pidFile)
		if err != nil {
			exitWithError(err)
		}
		// Remove the pid-file when exiting
		defer func() {
			if err := os.Remove(pidFile); err != nil {
				log.Error(err)
			}
		}()
		pid := os.Getpid()
		if _, err := f.WriteString(strconv.Itoa(pid)); err != nil {
			exitWithError(err)
		}
	}

	config := types.Configuration{
		Debug:             debug,
		CaptureFile:       captureFile(),
		MTU:               mtu,
		Subnet:            "192.168.127.0/24",
		GatewayIP:         gatewayIP,
		GatewayMacAddress: "5a:94:ef:e4:0c:dd",
		DHCPStaticLeases: map[string]string{
			"192.168.127.2": "5a:94:ef:e4:0c:ee",
		},
		DNS: []types.Zone{
			{
				Name: "containers.internal.",
				Records: []types.Record{
					{
						Name: gateway,
						IP:   net.ParseIP(gatewayIP),
					},
					{
						Name: host,
						IP:   net.ParseIP(hostIP),
					},
				},
			},
			{
				Name: "docker.internal.",
				Records: []types.Record{
					{
						Name: gateway,
						IP:   net.ParseIP(gatewayIP),
					},
					{
						Name: host,
						IP:   net.ParseIP(hostIP),
					},
				},
			},
		},
		DNSSearchDomains: searchDomains(),
		Forwards:         getForwardsMap(sshPort, sshHostPort),
		NAT: map[string]string{
			hostIP: "127.0.0.1",
		},
		GatewayVirtualIPs: []string{hostIP},
		VpnKitUUIDMacAddresses: map[string]string{
			"c3d68012-0208-11ea-9fd7-f2189899ab08": "5a:94:ef:e4:0c:ee",
		},
		Protocol: protocol,
	}

	groupErrs.Go(func() error {
		return run(ctx, groupErrs, &config, endpoints)
	})

	// Wait for something to happen
	groupErrs.Go(func() error {
		select {
		// Catch signals so exits are graceful and defers can run
		case <-sigChan:
			cancel()
			return errors.New("signal caught")
		case <-ctx.Done():
			return nil
		}
	})
	// Wait for all of the go funcs to finish up
	if err := groupErrs.Wait(); err != nil {
		log.Errorf("gvproxy exiting: %v", err)
		exitCode = 1
	}
}

func getForwardsMap(sshPort int, sshHostPort string) map[string]string {
	if sshPort == -1 {
		return map[string]string{}
	}
	return map[string]string{
		fmt.Sprintf("127.0.0.1:%d", sshPort): sshHostPort,
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

func run(ctx context.Context, g *errgroup.Group, configuration *types.Configuration, endpoints []string) error {
	vn, err := virtualnetwork.New(configuration)
	if err != nil {
		return err
	}
	log.Info("waiting for clients...")

	for _, endpoint := range endpoints {
		log.Infof("listening %s", endpoint)
		ln, err := transport.Listen(endpoint)
		if err != nil {
			return errors.Wrap(err, "cannot listen")
		}
		httpServe(ctx, g, ln, withProfiler(vn))
	}

	ln, err := vn.Listen("tcp", fmt.Sprintf("%s:80", gatewayIP))
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("/services/forwarder/all", vn.Mux())
	mux.Handle("/services/forwarder/expose", vn.Mux())
	mux.Handle("/services/forwarder/unexpose", vn.Mux())
	httpServe(ctx, g, ln, mux)

	if debug {
		g.Go(func() error {
		debugLog:
			for {
				select {
				case <-time.After(5 * time.Second):
					log.Debugf("%v sent to the VM, %v received from the VM\n", humanize.Bytes(vn.BytesSent()), humanize.Bytes(vn.BytesReceived()))
				case <-ctx.Done():
					break debugLog
				}
			}
			return nil
		})
	}

	if vpnkitSocket != "" {
		vpnkitListener, err := transport.Listen(vpnkitSocket)
		if err != nil {
			return errors.Wrap(err, "vpnkit listen error")
		}
		g.Go(func() error {
		vpnloop:
			for {
				select {
				case <-ctx.Done():
					break vpnloop
				default:
					// pass through
				}
				conn, err := vpnkitListener.Accept()
				if err != nil {
					log.Errorf("vpnkit accept error: %s", err)
					continue
				}
				g.Go(func() error {
					return vn.AcceptVpnKit(conn)
				})
			}
			return nil
		})
	}

	if qemuSocket != "" {
		qemuListener, err := transport.Listen(qemuSocket)
		if err != nil {
			return errors.Wrap(err, "qemu listen error")
		}

		g.Go(func() error {
			<-ctx.Done()
			if err := qemuListener.Close(); err != nil {
				log.Errorf("error closing %s: %q", qemuSocket, err)
			}
			return os.Remove(qemuSocket)
		})

		g.Go(func() error {
			conn, err := qemuListener.Accept()
			if err != nil {
				return errors.Wrap(err, "qemu accept error")
			}
			return vn.AcceptQemu(ctx, conn)
		})
	}

	if bessSocket != "" {
		bessListener, err := transport.Listen(bessSocket)
		if err != nil {
			return errors.Wrap(err, "bess listen error")
		}

		g.Go(func() error {
			<-ctx.Done()
			if err := bessListener.Close(); err != nil {
				log.Errorf("error closing %s: %q", bessSocket, err)
			}
			return os.Remove(bessSocket)
		})

		g.Go(func() error {
			conn, err := bessListener.Accept()
			if err != nil {
				return errors.Wrap(err, "bess accept error")

			}
			return vn.AcceptBess(ctx, conn)
		})
	}

	if vfkitSocket != "" {
		conn, err := transport.ListenUnixgram(vfkitSocket)
		if err != nil {
			return errors.Wrap(err, "vfkit listen error")
		}

		g.Go(func() error {
			<-ctx.Done()
			if err := conn.Close(); err != nil {
				log.Errorf("error closing %s: %q", vfkitSocket, err)
			}
			return os.Remove(vfkitSocket)
		})

		g.Go(func() error {
			vfkitConn, err := transport.AcceptVfkit(conn)
			if err != nil {
				return errors.Wrap(err, "vfkit accept error")
			}
			return vn.AcceptVfkit(ctx, vfkitConn)
		})
	}

	if stdioSocket != "" {
		g.Go(func() error {
			conn := stdio.GetStdioConn()
			return vn.AcceptStdio(ctx, conn)
		})
	}

	for i := 0; i < len(forwardSocket); i++ {
		var (
			src *url.URL
			err error
		)
		if strings.Contains(forwardSocket[i], "://") {
			src, err = url.Parse(forwardSocket[i])
			if err != nil {
				return err
			}
		} else {
			src = &url.URL{
				Scheme: "unix",
				Path:   forwardSocket[i],
			}
		}

		dest := &url.URL{
			Scheme: "ssh",
			User:   url.User(forwardUser[i]),
			Host:   sshHostPort,
			Path:   forwardDest[i],
		}
		j := i
		g.Go(func() error {
			defer os.Remove(forwardSocket[j])
			forward, err := sshclient.CreateSSHForward(ctx, src, dest, forwardIdentify[j], vn)
			if err != nil {
				return err
			}
			go func() {
				<-ctx.Done()
				// Abort pending accepts
				forward.Close()
			}()
		loop:
			for {
				select {
				case <-ctx.Done():
					break loop
				default:
					// proceed
				}
				err := forward.AcceptAndTunnel(ctx)
				if err != nil {
					log.Debugf("Error occurred handling ssh forwarded connection: %q", err)
				}
			}
			return nil
		})
	}

	return nil
}

func httpServe(ctx context.Context, g *errgroup.Group, ln net.Listener, mux http.Handler) {
	g.Go(func() error {
		<-ctx.Done()
		return ln.Close()
	})
	g.Go(func() error {
		s := &http.Server{
			Handler:      mux,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
		}
		err := s.Serve(ln)
		if err != nil {
			if err != http.ErrServerClosed {
				return err
			}
			return err
		}
		return nil
	})
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

func exitWithError(err error) {
	log.Error(err)
	os.Exit(1)
}

func searchDomains() []string {
	if runtime.GOOS == "darwin" || runtime.GOOS == "linux" {
		f, err := os.Open("/etc/resolv.conf")
		if err != nil {
			log.Errorf("open file error: %v", err)
			return nil
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		searchPrefix := "search "
		for sc.Scan() {
			if strings.HasPrefix(sc.Text(), searchPrefix) {
				searchDomains := strings.Split(strings.TrimPrefix(sc.Text(), searchPrefix), " ")
				log.Debugf("Using search domains: %v", searchDomains)
				return searchDomains
			}
		}
		if err := sc.Err(); err != nil {
			log.Errorf("scan file error: %v", err)
			return nil
		}
	}
	return nil
}
