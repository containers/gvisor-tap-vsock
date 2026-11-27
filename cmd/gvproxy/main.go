package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
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
	"github.com/containers/gvisor-tap-vsock/pkg/notification"
	"github.com/containers/gvisor-tap-vsock/pkg/sshclient"
	"github.com/containers/gvisor-tap-vsock/pkg/tokenauth"
	"github.com/containers/gvisor-tap-vsock/pkg/transport"
	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/containers/gvisor-tap-vsock/pkg/virtualnetwork"
	"github.com/containers/winquit/pkg/winquit"
	humanize "github.com/dustin/go-humanize"
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
	if config.RequireOwnerLease {
		lease := os.NewFile(3, "gateway-supervisor-lease")
		if lease == nil {
			log.Fatal("gateway supervisor lease is missing")
		}
		info, err := lease.Stat()
		if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
			log.Fatal("gateway supervisor lease is invalid")
		}
		defer lease.Close()
		go func() {
			_, _ = io.Copy(io.Discard, lease)
			cancel()
		}()
	}
	// Make this the last defer statement in the stack. The closure is required
	// because deferred arguments are evaluated immediately; log.Exit(exitCode)
	// would always observe the initial zero value and mask startup failures.
	defer func() { log.Exit(exitCode) }()

	// Create a PID file if requested
	if config.PIDFile != "" {
		pidStr := strconv.Itoa(os.Getpid())
		if err := os.WriteFile(config.PIDFile, []byte(pidStr), 0o600); err != nil {
			log.Errorf("failed to write pidfile: %s", err.Error())
			return
		}
		// Remove the pid-file when exiting
		defer func() {
			if err := os.Remove(config.PIDFile); err != nil {
				log.Errorf("failed to remove pidfile: %s", err.Error())
			}
		}()
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

func validateEgressPolicyAPIToken(required bool, token string) error {
	if required && token == "" {
		return errors.New("API token is required when exposing the services API or enabling egress policy")
	}
	return nil
}

func run(ctx context.Context, g *errgroup.Group, config *GvproxyConfig) error {
	// Load authentication before starting listeners. Egress policy mode must
	// never expose the policy or service API through the legacy open mode.
	apiToken, err := tokenauth.ReadToken(config.APITokenFile)
	if err != nil {
		return err
	}
	requireAPIToken := config.RequireEgressPolicy || config.Stack.EgressPolicy != nil || config.Services != ""
	if err := validateEgressPolicyAPIToken(requireAPIToken, apiToken); err != nil {
		return err
	}

	vn, err := virtualnetwork.New(&config.Stack, config.RequireEgressPolicy)
	if err != nil {
		return err
	}
	if apiToken != "" {
		vn.SetAPIToken(apiToken)
		log.Debug("API authentication enabled")
	} else {
		log.Warning("No API token configured, API authentication disabled (backwards compatibility mode)")
	}
	vn.SetEgressPolicyLoader(func() (*types.EgressPolicy, error) {
		if config.ConfigPath == "" {
			return nil, errors.New("gvproxy was not started with -config")
		}
		return LoadEgressPolicyFromFile(config.ConfigPath)
	})

	g.Go(func() error {
		<-ctx.Done()
		if err := vn.Close(); err != nil {
			log.Errorf("error shutting down virtual network: %q", err)
		}
		return err
	})

	// SIGHUP reloads only the egress policy. Invalid updates are rejected and
	// the previous immutable snapshot remains active.
	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
	g.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-sighup:
				if config.ConfigPath == "" {
					log.Warning("SIGHUP ignored: gvproxy was not started with -config")
					continue
				}
				if err := vn.ReloadEgressPolicy(); err != nil {
					log.Errorf("egress policy reload rejected: %v", err)
					continue
				}
				log.Infof("egress policy reloaded revision=%s", vn.EgressPolicyRevision())
			}
		}
	})

	log.Info("waiting for clients...")

	// Initializing notificationSender here because NewNotificationSender always returns a valid object (a no-op sender when socket is empty),
	// removing the need for nil checks at every Send() call.
	notificationSender := notification.NewNotificationSender(config.NotificationSocket)
	if config.NotificationSocket != "" {
		g.Go(func() error {
			notificationSender.Start(ctx)
			return nil
		})
	}
	vn.SetNotificationSender(notificationSender)
	for _, endpoint := range config.Listen {
		log.Infof("listening %s", endpoint)
		ln, err := transport.Listen(endpoint)
		if err != nil {
			return fmt.Errorf("cannot listen: %w", err)
		}
		httpServe(ctx, g, ln, withProfiler(vn))
	}
	notificationSender.Send(types.NotificationMessage{NotificationType: types.Ready})

	if config.Services != "" {
		log.Infof("enabling services API. Listening %s", config.Services)
		ln, err := transport.Listen(config.Services)
		if err != nil {
			return fmt.Errorf("cannot listen: %w", err)
		}
		httpServe(ctx, g, ln, vn.ServicesMux())
	}

	ln, err := vn.Listen("tcp", fmt.Sprintf("%s:80", config.Stack.GatewayIP))
	if err != nil {
		return err
	}
	httpServe(ctx, g, ln, vn.GatewayMux())

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
			notificationSender.Send(types.NotificationMessage{NotificationType: types.HypervisorError})
			return fmt.Errorf("vpnkit listen error: %w", err)
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
					notificationSender.Send(types.NotificationMessage{NotificationType: types.HypervisorError})
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
			notificationSender.Send(types.NotificationMessage{NotificationType: types.HypervisorError})
			return fmt.Errorf("qemu listen error: %w", err)
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
				notificationSender.Send(types.NotificationMessage{NotificationType: types.HypervisorError})
				return fmt.Errorf("qemu accept error: %w", err)
			}
			return vn.AcceptQemu(ctx, conn)
		})
	}

	if config.Interfaces.Bess != "" {
		bessListener, err := transport.Listen(config.Interfaces.Bess)
		if err != nil {
			notificationSender.Send(types.NotificationMessage{NotificationType: types.HypervisorError})
			return fmt.Errorf("bess listen error: %w", err)
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
				notificationSender.Send(types.NotificationMessage{NotificationType: types.HypervisorError})
				return fmt.Errorf("bess accept error: %w", err)
			}
			return vn.AcceptBess(ctx, conn)
		})
	}

	if config.Interfaces.Vfkit != "" {
		conn, err := transport.ListenUnixgram(config.Interfaces.Vfkit)
		if err != nil {
			notificationSender.Send(types.NotificationMessage{NotificationType: types.HypervisorError})
			return fmt.Errorf("vfkit listen error: %w", err)
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
				notificationSender.Send(types.NotificationMessage{NotificationType: types.HypervisorError})
				return fmt.Errorf("vfkit accept error: %w", err)
			}

			return vn.AcceptVfkit(ctx, vfkitConn)
		})
	}

	if config.Interfaces.Stdio != "" {
		g.Go(func() error {
			conn := stdio.GetStdioConn()
			if err := vn.AcceptStdio(ctx, conn); err != nil {
				notificationSender.Send(types.NotificationMessage{NotificationType: types.HypervisorError})
				return err
			}
			return nil
		})
	}

	sshForwards := make([]sshclient.ForwardConfig, len(config.Forwards))
	for i := range config.Forwards {
		forward := config.Forwards[i]
		sshForwards[i] = sshclient.ForwardConfig{
			Source: forward.Socket,
			Destination: &url.URL{
				Scheme: "ssh",
				User:   url.User(forward.User),
				Host:   net.JoinHostPort(config.Stack.DeviceIP, "22"),
				Path:   forward.Dest,
			},
			Identity: forward.Identity,
		}
	}
	if err := sshclient.SetupForwards(ctx, g, sshForwards, vn); err != nil {
		return err
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
	vnHandler := vn.Mux()
	if !InDebugMode() {
		return vnHandler
	}
	// Register the pprof debug endpoints on a separate outer mux rather than
	// on vnHandler itself: vnHandler is audit-logged (see pkg/apilog), and we
	// don't want debug/profiling requests to show up in that audit trail.
	mux := http.NewServeMux()
	mux.Handle("/", vnHandler)
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
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
