package sshclient

import (
	"context"
	"net"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/transport"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

// ForwardConfig describes a local socket and its SSH destination.
// Source is the socket to listen on, given either as a plain
// filesystem path (a unix socket) or as a URL (unix://, npipe://).
type ForwardConfig struct {
	Source      string
	Destination *url.URL
	Identity    string
}

// SetupForwards sets up and serves each configured SSH forward.
//
// For unix socket sources, a socket file left behind by a previous run
// is removed before listening (see removeStaleSocket), and the socket
// file is removed again when the forward is torn down. As this results
// in file deletion on the host, Source must come from trusted local
// configuration, never from untrusted input.
func SetupForwards(ctx context.Context, g *errgroup.Group, forwards []ForwardConfig, dialer SSHDialer) error {
	for i := range forwards {
		src, err := parseForwardSource(forwards[i].Source)
		if err != nil {
			return err
		}

		forwardConfig := forwards[i]
		socketPath := ""
		if src.Scheme == "unix" {
			socketPath = transport.UnixSocketPath(src, runtime.GOOS)
		}
		g.Go(func() error {
			// Remove sockets left behind by a crashed run. Not done in
			// listenUnix() as its paths can be guest-controlled (CVE-2026-107935).
			if err := removeStaleSocket(socketPath); err != nil {
				return err
			}
			forward, err := CreateSSHForward(ctx, src, forwardConfig.Destination, forwardConfig.Identity, dialer)
			if err != nil {
				return err
			}
			if socketPath != "" {
				defer os.Remove(socketPath)
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
				if err := forward.AcceptAndTunnel(ctx); err != nil {
					logrus.Debugf("Error occurred handling ssh forwarded connection: %q", err)
				}
			}
			return nil
		})
	}

	return nil
}

func parseForwardSource(source string) (*url.URL, error) {
	if strings.Contains(source, "://") {
		return url.Parse(source)
	}
	return &url.URL{
		Scheme: "unix",
		Path:   source,
	}, nil
}

// removeStaleSocket removes the unix socket file at path if one is left
// behind, typically by a previous crashed run, so that net.Listen() can
// succeed on that path. It is a no-op when no file exists at path, and it
// never removes anything but a socket file: a pre-existing regular file
// makes net.Listen() fail, but it is not ours to delete.
// A socket is only considered stale when connecting to it is refused, so
// that a socket still served by another running process is left alone.
func removeStaleSocket(path string) error {
	if path == "" {
		return nil
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return nil
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return nil
	}
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err == nil {
		conn.Close()
		return nil
	}
	if !isConnRefused(err) {
		return nil
	}
	return os.Remove(path)
}
