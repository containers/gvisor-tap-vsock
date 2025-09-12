package main

import (
	"flag"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"runtime"
	"slices"
	"strings"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	yaml "gopkg.in/yaml.v3"
)

const (
	// 	gatewayIP   = "192.168.127.1"
	sshHostPort = "192.168.127.2:22"
	hostIP      = "192.168.127.254"
	host        = "host"
	gateway     = "gateway"
)

type GvproxyArgs struct {
	config            string
	endpoints         arrayFlags
	debug             bool
	mtu               int
	sshPort           int
	vpnkitSocket      string
	qemuSocket        string
	bessSocket        string
	stdioSocket       string
	vfkitSocket       string
	forwardSocket     arrayFlags
	forwardDest       arrayFlags
	forwardUser       arrayFlags
	forwardIdentify   arrayFlags
	pidFile           string
	pcapFile          string
	logFile           string
	servicesEndpoint  string
	ec2MetadataAccess bool
}

type GvproxyConfig struct {
	Listen     []string            `yaml:"listen,omitempty"`
	LogLevel   string              `yaml:"log-level,omitempty"`
	Stack      types.Configuration `yaml:"stack,omitempty"`
	Interfaces struct {
		VPNKit string `yaml:"vpnkit,omitempty"`
		Qemu   string `yaml:"qemu,omitempty"`
		Bess   string `yaml:"bess,omitempty"`
		Stdio  string `yaml:"stdio,omitempty"`
		Vfkit  string `yaml:"vfkit,omitempty"`
	} `yaml:"interfaces,omitempty"`
	Forwards          []GvproxyConfigForward `yaml:"forwards,omitempty"`
	PIDFile           string                 `yaml:"pid-file,omitempty"`
	LogFile           string                 `yaml:"log-file,omitempty"`
	Services          string                 `yaml:"services,omitempty"`
	Ec2MetadataAccess bool                   `yaml:"ec2-metadata-access,omitempty"`
}

type GvproxyConfigForward struct {
	Socket   string `yaml:"socket,omitempty"`
	Dest     string `yaml:"dest,omitempty"`
	User     string `yaml:"user,omitempty"`
	Identity string `yaml:"identity,omitempty"`
}

func GvproxyVersion() string {
	return types.NewVersion("gvproxy").String()
}

func GvproxyInit() (*GvproxyConfig, error) {
	var args GvproxyArgs
	var config GvproxyConfig

	version := types.NewVersion("gvproxy")
	version.AddFlag()

	// Pass it to the testable function
	_, err := GvproxyArgParse(flag.CommandLine, &args, os.Args[1:])
	if err != nil {
		return nil, fmt.Errorf("failed to parse command line arguments: %w", err)
	}

	if version.ShowVersion() {
		fmt.Println(version.String())
		os.Exit(0)
	}

	// Init config if provided
	if args.config != "" {
		content, err := os.ReadFile(args.config)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}

		if err := yaml.Unmarshal(content, &config); err != nil {
			return nil, fmt.Errorf("failed to parse configuration: %w", err)
		}
	}

	// Pass it to the testable function
	return GvproxyConfigure(&config, &args, version.String())
}

func GvproxyArgParse(flagSet *flag.FlagSet, args *GvproxyArgs, argv []string) (*GvproxyArgs, error) {
	flagSet.StringVar(&args.config, "config", "", "Use configuration file with command line override")
	flagSet.Var(&args.endpoints, "listen", "control endpoint")
	flagSet.BoolVar(&args.debug, "debug", false, "Print debug info")
	flagSet.StringVar(&args.pcapFile, "pcap", "", "Capture network traffic to a pcap file")
	flagSet.IntVar(&args.mtu, "mtu", 0, "Set the MTU (default: 1500)")
	flagSet.IntVar(&args.sshPort, "ssh-port", 2222, "Port to access the guest virtual machine. Must be between 1024 and 65535")
	flagSet.StringVar(&args.vpnkitSocket, "listen-vpnkit", "", "VPNKit socket to be used by Hyperkit")
	flagSet.StringVar(&args.qemuSocket, "listen-qemu", "", "Socket to be used by Qemu")
	flagSet.StringVar(&args.bessSocket, "listen-bess", "", "unixpacket socket to be used by Bess-compatible applications")
	flagSet.StringVar(&args.stdioSocket, "listen-stdio", "", "accept stdio pipe")
	flagSet.StringVar(&args.vfkitSocket, "listen-vfkit", "", "unixgram socket to be used by vfkit-compatible applications")
	flagSet.Var(&args.forwardSocket, "forward-sock", "Forwards a unix socket to the guest virtual machine over SSH")
	flagSet.Var(&args.forwardDest, "forward-dest", "Forwards a unix socket to the guest virtual machine over SSH")
	flagSet.Var(&args.forwardUser, "forward-user", "SSH user to use for unix socket forward")
	flagSet.Var(&args.forwardIdentify, "forward-identity", "Path to SSH identity key for forwarding")
	flagSet.StringVar(&args.pidFile, "pid-file", "", "Generate a file with the PID in it")
	flagSet.StringVar(&args.logFile, "log-file", "", "Output log messages (logrus) to a given file path")
	flagSet.StringVar(&args.servicesEndpoint, "services", "", "Exposes the same HTTP API as the --listen flag, without the /connect endpoint")
	flagSet.BoolVar(&args.ec2MetadataAccess, "ec2-metadata-access", false, "Permits access to EC2 Metadata Service (TCP only)")
	if err := flagSet.Parse(argv); err != nil {
		return nil, err
	}

	return args, nil
}

func GvproxyConfigure(config *GvproxyConfig, args *GvproxyArgs, version string) (*GvproxyConfig, error) {
	if args.debug {
		config.LogLevel = "debug"
	}

	// Set log level
	if logLevel, err := log.ParseLevel(strings.ToLower(config.LogLevel)); err != nil {
		log.Warningf("bad log level \"%s\", falling back to \"info\"", config.LogLevel)
		log.SetLevel(log.InfoLevel)
	} else {
		log.SetLevel(logLevel)
	}

	// Set log file
	if config.LogFile != "" {
		lf, err := os.Create(config.LogFile)
		if err != nil {
			return config, fmt.Errorf("unable to open log file %s", config.LogFile)
		}
		log.DeferExitHandler(func() {
			if err := lf.Close(); err != nil {
				fmt.Printf("unable to close log-file: %q\n", err)
			}
		})
		log.SetOutput(lf)

		// If debug is set, lets seed the log file with some basic information
		// about the environment and how it was called
		log.Debugf("gvproxy version: %q", version)
		log.Debugf("os: %q arch: %q", runtime.GOOS, runtime.GOARCH)
		log.Debugf("command line: %q", os.Args)
	}

	// Set defaults
	if config.LogLevel == "" {
		config.LogLevel = "info"
	}
	if config.Stack.MTU == 0 {
		config.Stack.MTU = 1500
	}
	if config.Stack.Subnet == "" {
		config.Stack.Subnet = "192.168.127.0/24"
	}

	// Parse subnet address for further use
	naddr, err := netip.ParsePrefix(config.Stack.Subnet)
	if err != nil {
		return config, fmt.Errorf("failed to parse subnet: %w", err)
	}
	fuaddr, err := getFirstUsableIPFromSubnet(naddr)
	if err != nil {
		return config, fmt.Errorf("failed to identify first usable address in subnet: %w", err)
	}
	luaddr, err := getLastUsableIPFromSubnet(naddr)
	if err != nil {
		return config, fmt.Errorf("failed to identify last usable address in subnet: %w", err)
	}

	if config.Stack.GatewayIP == "" {
		config.Stack.GatewayIP = fuaddr.String()
	}
	if config.Stack.GatewayMacAddress == "" {
		config.Stack.GatewayMacAddress = "5a:94:ef:e4:0c:dd"
	}
	if len(config.Stack.NAT) == 0 {
		config.Stack.NAT = map[string]string{
			luaddr.String(): "127.0.0.1",
		}
	}
	if len(config.Stack.GatewayVirtualIPs) == 0 {
		config.Stack.GatewayVirtualIPs = []string{
			luaddr.String(),
		}
	}

	// Default DNS zone enabled only for the default mode
	// Default DNS search domains enabled only for the default mode
	// Default forwards enabled only for the default mode
	// Default static leases enabled only for the default mode
	// Default vpnkit mac addresses enabled only for the default mode

	// Patch config with CLI args
	if args.logFile != "" {
		config.LogFile = args.logFile
	}
	if args.qemuSocket != "" {
		config.Interfaces.Qemu = args.qemuSocket
	}
	if args.bessSocket != "" {
		config.Interfaces.Bess = args.bessSocket
	}
	if args.vfkitSocket != "" {
		config.Interfaces.Vfkit = args.vfkitSocket
	}
	if args.vpnkitSocket != "" {
		config.Interfaces.VPNKit = args.vpnkitSocket
	}
	if args.pidFile != "" {
		config.PIDFile = args.pidFile
	}
	if len(args.endpoints) > 0 {
		config.Listen = args.endpoints
	}
	if args.servicesEndpoint != "" {
		config.Services = args.servicesEndpoint
	}
	if args.ec2MetadataAccess {
		config.Ec2MetadataAccess = true
	}
	if args.mtu != 0 {
		config.Stack.MTU = args.mtu
	}

	// Make sure the qemu socket provided is valid syntax
	if config.Interfaces.Qemu != "" {
		uri, err := url.Parse(config.Interfaces.Qemu)
		if err != nil || uri == nil {
			return config, errors.Wrapf(err, "invalid value for qemu listen address")
		}
		if _, err := os.Stat(uri.Path); err == nil && uri.Scheme == "unix" {
			return config, errors.Errorf("%q already exists", uri.Path)
		}
	}
	if config.Interfaces.Bess != "" {
		uri, err := url.Parse(config.Interfaces.Bess)
		if err != nil || uri == nil {
			return config, errors.Wrapf(err, "invalid value for bess listen address")
		}
		if uri.Scheme != "unixpacket" {
			return config, errors.New("bess listen address must be unixpacket:// address")
		}
		if _, err := os.Stat(uri.Path); err == nil {
			return config, fmt.Errorf("%q already exists", uri.Path)
		}
	}
	if config.Interfaces.Vfkit != "" {
		uri, err := url.Parse(config.Interfaces.Vfkit)
		if err != nil || uri == nil {
			return config, errors.Wrapf(err, "invalid value for vfkit listen address")
		}
		if uri.Scheme != "unixgram" {
			return config, errors.New("vfkit listen address must be unixgram:// address")
		}
		if _, err := os.Stat(uri.Path); err == nil {
			return config, errors.Errorf("%q already exists", uri.Path)
		}
	}

	if config.Interfaces.VPNKit != "" && config.Interfaces.Qemu != "" {
		return config, errors.New("cannot use qemu and vpnkit protocol at the same time")
	}
	if config.Interfaces.VPNKit != "" && config.Interfaces.Bess != "" {
		return config, errors.New("cannot use bess and vpnkit protocol at the same time")
	}
	if config.Interfaces.Qemu != "" && config.Interfaces.Bess != "" {
		return config, errors.New("cannot use qemu and bess protocol at the same time")
	}

	if args.config != "" {
		if slices.Contains(os.Args, "-ssh-port") || slices.Contains(os.Args, "--ssh-port") {
			log.Warningf("CLI argument \"-ssh-port\" is unavailable with config file. You need to add \"127.0.0.1:%d: 192.168.127.2:22\" entry into .stack.forwards in \"\" instead", args.sshPort)
		}
	}

	config.Stack.Protocol = types.HyperKitProtocol
	if config.Interfaces.Qemu != "" {
		config.Stack.Protocol = types.QemuProtocol
	}
	if config.Interfaces.Bess != "" {
		config.Stack.Protocol = types.BessProtocol
	}
	if config.Interfaces.Vfkit != "" {
		config.Stack.Protocol = types.VfkitProtocol
	}

	if InDebugMode() {
		config.Stack.Debug = true
	}

	// Handle the default behavior without config
	if args.config == "" {
		if args.sshPort != -1 && args.sshPort < 1024 || args.sshPort > 65535 {
			return config, errors.New("ssh-port value must be between 1024 and 65535")
		}

		config.Stack.CaptureFile = args.pcapFile

		config.Stack.DNS = []types.Zone{
			{
				Name: "containers.internal.",
				Records: []types.Record{
					{
						Name: gateway,
						IP:   net.ParseIP(config.Stack.GatewayIP),
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
						IP:   net.ParseIP(config.Stack.GatewayIP),
					},
					{
						Name: host,
						IP:   net.ParseIP(hostIP),
					},
				},
			},
		}
		config.Stack.DNSSearchDomains = searchDomains()
		config.Stack.Forwards = getForwardsMap(args.sshPort, sshHostPort)
		config.Stack.DHCPStaticLeases = map[string]string{
			"192.168.127.2": "5a:94:ef:e4:0c:ee",
		}
		config.Stack.VpnKitUUIDMacAddresses = map[string]string{
			"c3d68012-0208-11ea-9fd7-f2189899ab08": "5a:94:ef:e4:0c:ee",
		}
	}

	// Add SSH forwards from CLI args
	if c := len(args.forwardSocket); c != len(args.forwardDest) || c != len(args.forwardUser) || c != len(args.forwardIdentify) {
		return config, errors.New("--forward-sock, --forward-dest, --forward-user, and --forward-identity must all be specified together, " +
			"the same number of times, or not at all")
	}

	for i := range args.forwardSocket {
		config.Forwards = append(config.Forwards, GvproxyConfigForward{
			Socket:   args.forwardSocket[i],
			Dest:     args.forwardDest[i],
			User:     args.forwardUser[i],
			Identity: args.forwardIdentify[i],
		})
	}

	// Validate SSH forward rules
	for _, v := range config.Forwards {
		_, err := os.Stat(v.Identity)
		if err != nil {
			return config, errors.Wrapf(err, "Identity file \"%s\" can't be loaded", v.Identity)
		}
	}

	return config, nil
}

func getFirstUsableIPFromSubnet(network netip.Prefix) (netip.Addr, error) {
	// The network must have at least 5 IP addresses: network, broadcast, gateway, guest, and preferably host
	// v4/30 has only 2 devices, thus prefer at least v4/29 CIDR. This code works also for IPv6, just in case
	if (network.Bits() + 3) > network.Addr().BitLen() {
		return netip.Addr{}, errors.New("too small network")
	}

	b := network.Masked().Addr().AsSlice()
	b[len(b)-1] += 1

	addr, ok := netip.AddrFromSlice(b)
	if !ok {
		return netip.Addr{}, errors.New("bad ip address")
	}

	return addr, nil
}

func getLastUsableIPFromSubnet(network netip.Prefix) (netip.Addr, error) {
	// The network must have at least 5 IP addresses: network, broadcast, gateway, guest, and preferably host
	// v4/30 has only 2 devices, thus prefer at least v4/29 CIDR. This code works also for IPv6, just in case
	if (network.Bits() + 3) > network.Addr().BitLen() {
		return netip.Addr{}, errors.New("too small network")
	}

	var b = network.Masked().Addr().AsSlice()
	for i, v := range net.CIDRMask(network.Bits(), network.Addr().BitLen()) {
		b[i] += ^v
	}
	b[len(b)-1] -= 1

	addr, ok := netip.AddrFromSlice(b)
	if !ok {
		return netip.Addr{}, errors.New("bad ip address")
	}

	return addr, nil
}
