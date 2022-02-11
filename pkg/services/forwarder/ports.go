package forwarder

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/google/tcpproxy"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type PortsForwarder struct {
	stack *stack.Stack

	proxiesLock sync.Mutex
	proxies     map[string]proxy
}

type proxy struct {
	Local      string `json:"local"`
	Remote     string `json:"remote"`
	Protocol   string `json:"protocol"`
	underlying io.Closer
}

func NewPortsForwarder(s *stack.Stack) *PortsForwarder {
	return &PortsForwarder{
		stack:   s,
		proxies: make(map[string]proxy),
	}
}

func (f *PortsForwarder) Expose(protocol types.TransportProtocol, local, remote string) error {
	f.proxiesLock.Lock()
	defer f.proxiesLock.Unlock()
	if _, ok := f.proxies[local]; ok {
		return errors.New("proxy already running")
	}

	switch protocol {
	case types.UNIX:
		// parse URI for remote
		remoteURI, err := url.Parse(remote)
		if err != nil {
			return fmt.Errorf("failed to parse remote uri :%s : %w", remote, err)
		}

		// build the address from remoteURI
		remoteAddr := fmt.Sprintf("%s:%s", remoteURI.Hostname(), remoteURI.Port())

		// dialFn opens remote connection for the proxy
		var dialFn func(ctx context.Context, network, addr string) (conn net.Conn, e error)

		// dialFn is set based on the protocol provided by remoteURI.Scheme
		switch remoteURI.Scheme {
		case "ssh-tunnel": // unix-to-unix proxy (over SSH)
			// query string to map for the remoteURI contains ssh config info
			remoteQuery := remoteURI.Query()

			// username
			sshuser := firstValueOrEmpty(remoteQuery["user"])
			if sshuser == "" {
				return fmt.Errorf("user not provided for unix-ssh connection")
			}

			// key
			sshkeypath := firstValueOrEmpty(remoteQuery["key"])
			if sshkeypath == "" {
				return fmt.Errorf("key not provided for unix-ssh connection")
			}

			sshkeyBytes, err := ioutil.ReadFile(sshkeypath)
			if err != nil {
				return fmt.Errorf("failed to read ssh key: %s: %w", sshkeypath, err)
			}

			// passphrase
			passphrase := firstValueOrEmpty(remoteQuery["passphrase"])

			var sshsigner ssh.Signer

			if passphrase == "" {
				sshsigner, err = ssh.ParsePrivateKey(sshkeyBytes)
			} else {
				sshsigner, err = ssh.ParsePrivateKeyWithPassphrase(sshkeyBytes, []byte(passphrase))
			}

			// parse private key error?
			if err != nil {
				return fmt.Errorf("failed to parse ssh key: %s: %w", sshkeypath, err)
			}

			// default ssh port if not set
			if remoteURI.Port() == "" {
				remoteAddr = fmt.Sprintf("%s:%s", remoteURI.Hostname(), "22")
			}

			// build address
			address, err := tcpipAddress(1, remoteAddr)
			if err != nil {
				return err
			}

			// check the remoteURI path provided for nonsense
			if remoteURI.Path == "" || remoteURI.Path == "/" {
				return fmt.Errorf("remote uri must contain a path to a socket file")
			}

			// captured and used by dialFn
			var tcpConn *gonet.TCPConn
			var sshClient *ssh.Client
			var connLock sync.Mutex

			// handles getting underlying ssh connection, having this outside of
			// dialFn limits connLock to only the parts it's needed for in a way
			// that doesn't get racy.
			sshConnFn := func(ctx context.Context, network, addr string) (client *ssh.Client, err error) {
				connLock.Lock()
				defer connLock.Unlock()

				// check underlying tcpConn to see if it's closed
				if tcpConn != nil {
					if _, err := tcpConn.Read(make([]byte, 0)); err == io.EOF {
						tcpConn = nil // set back to nil to force reconnect
					}
				}

				// connect or reconnect to ssh
				if tcpConn == nil || sshClient == nil {
					// underlying connection to endpoint for the ssh client
					tcpConn, err := gonet.DialContextTCP(ctx, f.stack, address, ipv4.ProtocolNumber)
					if err != nil {
						return sshClient, err
					}

					// ssh client config that uses key authentication
					config := &ssh.ClientConfig{
						User: sshuser,
						Auth: []ssh.AuthMethod{
							ssh.PublicKeys(sshsigner),
						},
						// #nosec G106
						HostKeyCallback: ssh.InsecureIgnoreHostKey(),
						HostKeyAlgorithms: []string{
							ssh.KeyAlgoRSA,
							ssh.KeyAlgoDSA,
							ssh.KeyAlgoECDSA256,
							ssh.KeyAlgoECDSA384,
							ssh.KeyAlgoECDSA521,
							ssh.KeyAlgoED25519,
						},
						Timeout: 5 * time.Second,
					}

					// get an sshConn using the underlying gonet.TCPConn
					sshConn, chans, reqs, err := ssh.NewClientConn(tcpConn, addr, config)
					if err != nil {
						return sshClient, err
					}

					// build an ssh client using sshConn
					sshClient = ssh.NewClient(sshConn, chans, reqs)
				}

				return sshClient, err
			}

			// the dialFn for unix-to-unix over SSH
			dialFn = func(ctx context.Context, network, addr string) (conn net.Conn, e error) {
				// check or create new ssh connection
				sshClient, err = sshConnFn(ctx, network, addr)
				if err != nil {
					return nil, err
				}

				// connection using sshclient's dialer
				return sshClient.Dial("unix", remoteURI.Path)
			}

		case "tcp": // unix-to-tcp proxy
			// build address
			address, err := tcpipAddress(1, remoteAddr)
			if err != nil {
				return err
			}

			dialFn = func(ctx context.Context, network, addr string) (conn net.Conn, e error) {
				return gonet.DialContextTCP(ctx, f.stack, address, ipv4.ProtocolNumber)
			}

		default:
			return fmt.Errorf("remote protocol for unix forwarder is not implemented: %s", remoteURI.Scheme)
		}

		// build the tcp proxy
		var p tcpproxy.Proxy
		p.ListenFunc = func(_, socketPath string) (net.Listener, error) {
			// remove existing socket file
			if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
				return nil, err
			}

			return net.Listen("unix", socketPath) // override tcp to use unix socket
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

		f.proxies[key(protocol, local)] = proxy{
			Protocol:   "unix",
			Local:      local,
			Remote:     remote,
			underlying: &p,
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
		f.proxies[key(protocol, local)] = proxy{
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
			DialContext: func(ctx context.Context, network, addr string) (conn net.Conn, e error) {
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
		f.proxies[key(protocol, local)] = proxy{
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

func key(protocol types.TransportProtocol, local string) string {
	return fmt.Sprintf("%s/%s", protocol, local)
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

func (f *PortsForwarder) Mux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/all", func(w http.ResponseWriter, r *http.Request) {
		f.proxiesLock.Lock()
		defer f.proxiesLock.Unlock()
		ret := make([]proxy, 0)
		for _, proxy := range f.proxies {
			ret = append(ret, proxy)
		}
		sort.Slice(ret, func(i, j int) bool {
			if ret[i].Local == ret[j].Local {
				return ret[i].Protocol < ret[j].Protocol
			}
			return ret[i].Local < ret[j].Local
		})
		_ = json.NewEncoder(w).Encode(ret)
	})
	mux.HandleFunc("/expose", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "post only", http.StatusBadRequest)
			return
		}
		var req types.ExposeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.Protocol == "" {
			req.Protocol = types.TCP
		}

		// contains unparsed remote field
		remoteAddr := req.Remote

		// TCP and UDP rely on remote() to preparse the remote field
		if req.Protocol != types.UNIX {
			var err error
			remoteAddr, err = remote(req, r.RemoteAddr)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}

		if err := f.Expose(req.Protocol, req.Local, remoteAddr); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/unexpose", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "post only", http.StatusBadRequest)
			return
		}
		var req types.UnexposeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.Protocol == "" {
			req.Protocol = types.TCP
		}
		if err := f.Unexpose(req.Protocol, req.Local); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	return mux
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

	port, err := strconv.Atoi(split[1])
	if err != nil {
		return address, err

	}

	address = tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.Address(net.ParseIP(split[0]).To4()),
		Port: uint16(port),
	}

	return address, err
}
