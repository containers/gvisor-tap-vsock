package main

import (
	"bufio"
	"context"
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
	"github.com/containers/gvisor-tap-vsock/pkg/virtualnetwork"
	"github.com/containers/winquit/pkg/winquit"
	humanize "github.com/dustin/go-humanize"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

var (
	exitCode int
)

func main() {
	// Use config or fallback to original behavior
	config, err := GvproxyInit()
	if err != nil {
		log.Fatal(err.Error())
	}

	// Report version
	log.Info(GvproxyVersion())

	ctx, cancel := context.WithCancel(context.Background())
	// Make this the last defer statement in the stack
	defer log.Exit(exitCode)

	// Create a PID file if requested
	if config.PIDFile != "" {
		f, err := os.Create(config.PIDFile)
		if err != nil {
			log.Errorf("failed to create pidfile: %s", err.Error())
			return
		}
		// Remove the pid-file when exiting
		defer func() {
			if err := os.Remove(config.PIDFile); err != nil {
				log.Errorf("failed to remove pidfile: %s", err.Error())
			}
		}()
		pid := os.Getpid()
		if _, err := f.WriteString(strconv.Itoa(pid)); err != nil {
			log.Errorf("failed to write pidfile: %s", err.Error())
			return
		}
	}

	groupErrs, ctx := errgroup.WithContext(ctx)
	// Setup signal channel for catching user signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	// Intercept WM_QUIT/WM_CLOSE events if on Windows as SIGTERM (noop on other OSs)
	winquit.SimulateSigTermOnQuit(sigChan)

	groupErrs.Go(func() error {
		return run(ctx, groupErrs, config)
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

func InDebugMode() bool {
	return log.GetLevel().String() == "debug"
}

func run(ctx context.Context, g *errgroup.Group, config *GvproxyConfig) error {
	vn, err := virtualnetwork.New(&config.Stack)
	if err != nil {
		return err
	}
	log.Info("waiting for clients...")

	for _, endpoint := range config.Listen {
		log.Infof("listening %s", endpoint)
		ln, err := transport.Listen(endpoint)
		if err != nil {
			return errors.Wrap(err, "cannot listen")
		}
		httpServe(ctx, g, ln, withProfiler(vn))
	}

	if config.Services != "" {
		log.Infof("enabling services API. Listening %s", config.Services)
		ln, err := transport.Listen(config.Services)
		if err != nil {
			return errors.Wrap(err, "cannot listen")
		}
		httpServe(ctx, g, ln, vn.ServicesMux())
	}

	ln, err := vn.Listen("tcp", fmt.Sprintf("%s:80", config.Stack.GatewayIP))
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("/services/forwarder/all", vn.Mux())
	mux.Handle("/services/forwarder/expose", vn.Mux())
	mux.Handle("/services/forwarder/unexpose", vn.Mux())
	httpServe(ctx, g, ln, mux)

	if InDebugMode() {
		g.Go(func() error {
		debugLog:
			for {
				select {
				case <-time.After(5 * time.Second):
					log.Debugf("%s sent to the VM, %s received from the VM\n", humanize.Bytes(vn.BytesSent()), humanize.Bytes(vn.BytesReceived()))
				case <-ctx.Done():
					break debugLog
				}
			}
			return nil
		})
	}

	if config.Interfaces.VPNKit != "" {
		vpnkitListener, err := transport.Listen(config.Interfaces.VPNKit)
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

	if config.Interfaces.Qemu != "" {
		qemuListener, err := transport.Listen(config.Interfaces.Qemu)
		if err != nil {
			return errors.Wrap(err, "qemu listen error")
		}

		g.Go(func() error {
			<-ctx.Done()
			if err := qemuListener.Close(); err != nil {
				log.Errorf("error closing %s: %q", config.Interfaces.Qemu, err)
			}
			return os.Remove(config.Interfaces.Qemu)
		})

		g.Go(func() error {
			conn, err := qemuListener.Accept()
			if err != nil {
				return errors.Wrap(err, "qemu accept error")
			}
			return vn.AcceptQemu(ctx, conn)
		})
	}

	if config.Interfaces.Bess != "" {
		bessListener, err := transport.Listen(config.Interfaces.Bess)
		if err != nil {
			return errors.Wrap(err, "bess listen error")
		}

		g.Go(func() error {
			<-ctx.Done()
			if err := bessListener.Close(); err != nil {
				log.Errorf("error closing %s: %q", config.Interfaces.Bess, err)
			}
			return os.Remove(config.Interfaces.Bess)
		})

		g.Go(func() error {
			conn, err := bessListener.Accept()
			if err != nil {
				return errors.Wrap(err, "bess accept error")
			}
			return vn.AcceptBess(ctx, conn)
		})
	}

	if config.Interfaces.Vfkit != "" {
		conn, err := transport.ListenUnixgram(config.Interfaces.Vfkit)
		if err != nil {
			return errors.Wrap(err, "vfkit listen error")
		}

		g.Go(func() error {
			<-ctx.Done()
			if err := conn.Close(); err != nil {
				log.Errorf("error closing %s: %q", config.Interfaces.Vfkit, err)
			}
			vfkitSocketURI, _ := url.Parse(config.Interfaces.Vfkit)
			return os.Remove(vfkitSocketURI.Path)
		})

		g.Go(func() error {
			vfkitConn, err := transport.AcceptVfkit(conn)
			if err != nil {
				return errors.Wrap(err, "vfkit accept error")
			}
			return vn.AcceptVfkit(ctx, vfkitConn)
		})
	}

	if config.Interfaces.Stdio != "" {
		g.Go(func() error {
			conn := stdio.GetStdioConn()
			return vn.AcceptStdio(ctx, conn)
		})
	}

	for i := range config.Forwards {
		var (
			src *url.URL
			err error
		)
		if strings.Contains(config.Forwards[i].Socket, "://") {
			src, err = url.Parse(config.Forwards[i].Socket)
			if err != nil {
				return err
			}
		} else {
			src = &url.URL{
				Scheme: "unix",
				Path:   config.Forwards[i].Socket,
			}
		}

		dest := &url.URL{
			Scheme: "ssh",
			User:   url.User(config.Forwards[i].User),
			Host:   sshHostPort,
			Path:   config.Forwards[i].Dest,
		}
		j := i
		g.Go(func() error {
			defer os.Remove(config.Forwards[j].Socket)
			forward, err := sshclient.CreateSSHForward(ctx, src, dest, config.Forwards[j].Identity, vn)
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
	if InDebugMode() {
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	}
	return mux
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
				return parseSearchString(sc.Text(), searchPrefix)
			}
		}
		if err := sc.Err(); err != nil {
			log.Errorf("scan file error: %v", err)
			return nil
		}
	}
	return nil
}

// Parse and sanitize search list
// macOS has limitation on number of domains (6) and general string length (256 characters)
// since glibc 2.26 Linux has no limitation on 'search' field
func parseSearchString(text, searchPrefix string) []string {
	// macOS allow only 265 characters in search list
	if runtime.GOOS == "darwin" && len(text) > 256 {
		log.Errorf("Search domains list is too long, it should not exceed 256 chars on macOS: %d", len(text))
		text = text[:256]
		lastSpace := strings.LastIndex(text, " ")
		if lastSpace != -1 {
			text = text[:lastSpace]
		}
	}

	searchDomains := strings.Split(strings.TrimPrefix(text, searchPrefix), " ")
	log.Debugf("Using search domains: %v", searchDomains)

	// macOS allow only 6 domains in search list
	if runtime.GOOS == "darwin" && len(searchDomains) > 6 {
		log.Errorf("Search domains list is too long, it should not exceed 6 domains on macOS: %d", len(searchDomains))
		searchDomains = searchDomains[:6]
	}

	return searchDomains
}
