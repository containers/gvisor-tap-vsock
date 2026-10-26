package sshclient

import (
	"context"
	"net/url"
	"os"
	"runtime"
	"strings"

	"github.com/containers/gvisor-tap-vsock/pkg/transport"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

// ForwardConfig describes a local socket and its SSH destination.
type ForwardConfig struct {
	Source      string
	Destination *url.URL
	Identity    string
}

// SetupForwards sets up and serves each configured SSH forward.
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
