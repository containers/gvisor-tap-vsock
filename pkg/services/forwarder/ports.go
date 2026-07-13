package forwarder

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/containers/gvisor-tap-vsock/pkg/sshclient"
	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/inetaf/tcpproxy"
	log "github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type ProxyKey string

type PortsForwarder struct {
	stack *stack.Stack

	proxiesLock sync.Mutex
	proxies     map[ProxyKey]Proxy
}

type Proxy struct {
	Local      string `json:"local"`
	Remote     string `json:"remote"`
	Protocol   string `json:"protocol"`
	underlying io.Closer
}

type gonetDialer struct {
	stack *stack.Stack
}

func (d *gonetDialer) DialContextTCP(ctx context.Context, addr string) (conn net.Conn, e error) {
	address, err := tcpipAddress(1, addr)
	if err != nil {
		return nil, err
	}

	return gonet.DialContextTCP(ctx, d.stack, address, ipv4.ProtocolNumber)
}

type CloseWrapper func() error

func (w CloseWrapper) Close() error {
	return w()
}

func NewPortsForwarder(s *stack.Stack) *PortsForwarder {
	return &PortsForwarder{
		stack:   s,
		proxies: make(map[ProxyKey]Proxy),
	}
}

func (f *PortsForwarder) Expose(protocol types.TransportProtocol, local, remote string) error {
	f.proxiesLock.Lock()
	defer f.proxiesLock.Unlock()

	if _, ok := f.proxies[key(protocol, local)]; ok {
		return fmt.Errorf("proxy already running for %s on %s", protocol, local)
	}

	switch protocol {
	case types.UNIX, types.NPIPE:
		// parse URI for remote
		remoteURI, err := url.Parse(remote)
		if err != nil {
			return fmt.Errorf("failed to parse remote uri :%s : %w", remote, err)
		}

		// build the address from remoteURI
		remoteAddr := net.JoinHostPort(remoteURI.Hostname(), remoteURI.Port())

		// dialFn opens remote connection for the proxy
		var dialFn func(ctx context.Context, network, addr string) (conn net.Conn, e error)

		var cleanup func()

		// dialFn is set based on the protocol provided by remoteURI.Scheme
		switch remoteURI.Scheme {
		case "ssh-tunnel": // unix-to-unix proxy (over SSH)
			// query string to map for the remoteURI contains ssh config info
			remoteQuery := remoteURI.Query()

			// key
			sshkeypath := firstValueOrEmpty(remoteQuery["key"])
			if sshkeypath == "" {
				return fmt.Errorf("key not provided for unix-ssh connection")
			}

			// passphrase
			passphrase := firstValueOrEmpty(remoteQuery["passphrase"])

			// default ssh port if not set
			if remoteURI.Port() == "" {
				remoteURI.Host = net.JoinHostPort(remoteURI.Hostname(), "22")
			}

			// check the remoteURI path provided for nonsense
			if remoteURI.Path == "" || remoteURI.Path == "/" {
				return fmt.Errorf("remote uri must contain a path to a socket file")
			}

			// captured and used by dialFn
			var sshForward *sshclient.SSHForward
			var connLock sync.Mutex

			dialFn = func(ctx context.Context, _, _ string) (net.Conn, error) {
				connLock.Lock()
				defer connLock.Unlock()

				if sshForward == nil {
					client, err := sshclient.CreateSSHForwardPassphrase(ctx, &url.URL{}, remoteURI, sshkeypath, passphrase, &gonetDialer{f.stack})
					if err != nil {
						return nil, err
					}
					sshForward = client
				}

				return sshForward.Tunnel(ctx)
			}

			cleanup = func() {
				if sshForward != nil {
					sshForward.Close()
				}
			}

		case "tcp": // unix-to-tcp proxy
			// build address
			address, err := tcpipAddress(1, remoteAddr)
			if err != nil {
				return err
			}

			dialFn = func(ctx context.Context, _, _ string) (conn net.Conn, e error) {
				return gonet.DialContextTCP(ctx, f.stack, address, ipv4.ProtocolNumber)
			}

		default:
			return fmt.Errorf("remote protocol for unix forwarder is not implemented: %s", remoteURI.Scheme)
		}

		// build the tcp proxy
		var p tcpproxy.Proxy
		switch protocol {
		case types.UNIX:
			p.ListenFunc = func(_, socketPath string) (net.Listener, error) {
				info, err := os.Stat(socketPath)
				if err != nil && !os.IsNotExist(err) {
					// any error other than file does not exist is fatal
					return nil, err
				}
				if err == nil {
					if info.Mode().Type() != fs.ModeSocket {
						return nil, fmt.Errorf("path already exists and is not a socket: %s", socketPath)
					}
					// remove existing socket file
					if err := os.Remove(socketPath); err != nil {
						return nil, err
					}
				}
				return net.Listen("unix", socketPath) // override tcp to use unix socket
			}
		case types.NPIPE:
			p.ListenFunc = func(_, socketPath string) (net.Listener, error) {
				npipeURI, err := url.Parse(socketPath)
				if err != nil {
					return nil, err
				}
				return sshclient.ListenNpipe(npipeURI)
			}
		}
		p.AddRoute(local, &tcpproxy.DialProxy{
			Addr:        remoteAddr,
			DialContext: dialFn,
		})
		if err := p.Start(); err != nil {
			return err
		}
		go func() {
			if err := p.Wait(); err != nil {
				log.Error(err)
			}
		}()
		f.proxies[key(protocol, local)] = Proxy{
			Protocol: string(protocol),
			Local:    local,
			Remote:   remote,
			underlying: CloseWrapper(func() error {
				if cleanup != nil {
					cleanup()
				}
				return p.Close()
			}),
		}
	case types.UDP:
		address, err := tcpipAddress(1, remote)
		if err != nil {
			return err
		}

		addr, err := net.ResolveUDPAddr("udp", local)
		if err != nil {
			return err
		}
		listener, err := net.ListenUDP("udp", addr)
		if err != nil {
			return err
		}
		p, err := NewUDPProxy(listener, func() (net.Conn, error) {
			return gonet.DialUDP(f.stack, nil, &address, ipv4.ProtocolNumber)
		})
		if err != nil {
			return err
		}
		go p.Run()
		f.proxies[key(protocol, local)] = Proxy{
			Protocol:   "udp",
			Local:      local,
			Remote:     remote,
			underlying: p,
		}
	case types.TCP:
		address, err := tcpipAddress(1, remote)
		if err != nil {
			return err
		}

		var p tcpproxy.Proxy
		p.AddRoute(local, &tcpproxy.DialProxy{
			Addr: remote,
			DialContext: func(ctx context.Context, _, _ string) (conn net.Conn, e error) {
				return gonet.DialContextTCP(ctx, f.stack, address, ipv4.ProtocolNumber)
			},
		})
		if err := p.Start(); err != nil {
			return err
		}
		go func() {
			if err := p.Wait(); err != nil {
				log.Error(err)
			}
		}()
		f.proxies[key(protocol, local)] = Proxy{
			Protocol:   "tcp",
			Local:      local,
			Remote:     remote,
			underlying: &p,
		}
	default:
		return fmt.Errorf("unknown protocol %s", protocol)
	}
	return nil
}

func key(protocol types.TransportProtocol, local string) ProxyKey {
	return ProxyKey(fmt.Sprintf("%s/%s", protocol, local))
}

func (f *PortsForwarder) Unexpose(protocol types.TransportProtocol, local string) error {
	f.proxiesLock.Lock()
	defer f.proxiesLock.Unlock()
	proxy, ok := f.proxies[key(protocol, local)]
	if !ok {
		return errors.New("proxy not found")
	}
	delete(f.proxies, key(protocol, local))
	return proxy.underlying.Close()
}

func (f *PortsForwarder) List() []Proxy {
	f.proxiesLock.Lock()
	defer f.proxiesLock.Unlock()
	ret := make([]Proxy, 0)
	for _, p := range f.proxies {
		ret = append(ret, p)
	}
	sort.Slice(ret, func(i, j int) bool {
		if ret[i].Local == ret[j].Local {
			return ret[i].Protocol < ret[j].Protocol
		}
		return ret[i].Local < ret[j].Local
	})
	return ret
}

func Remote(req types.ExposeRequest, ip string) (string, error) {
	return remote(req, ip)
}

// if the request doesn't have an IP in the remote field, use the IP from the incoming http request.
func remote(req types.ExposeRequest, ip string) (string, error) {
	remoteIP, _, err := net.SplitHostPort(req.Remote)
	if err != nil {
		return "", err
	}
	if remoteIP == "" {
		host, _, err := net.SplitHostPort(ip)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s%s", host, req.Remote), nil
	}
	return req.Remote, nil
}

// helper function for parsed URL query strings
func firstValueOrEmpty(x []string) string {
	if len(x) > 0 {
		return x[0]
	}
	return ""
}

// helper function to build tcpip address
func tcpipAddress(nicID tcpip.NICID, remote string) (address tcpip.FullAddress, err error) {

	// build the address manual way
	split := strings.Split(remote, ":")
	if len(split) != 2 {
		return address, errors.New("invalid remote addr")
	}

	port, err := strconv.ParseUint(split[1], 10, 16)
	if err != nil {
		return address, err

	}

	address = tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFrom4Slice(net.ParseIP(split[0]).To4()),
		Port: uint16(port),
	}

	return address, err
}
