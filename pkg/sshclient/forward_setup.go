package sshclient

import (
	"context"
	"net/url"
	"os"
	"strings"

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
		var (
			src *url.URL
			err error
		)
		if strings.Contains(forwards[i].Source, "://") {
			src, err = url.Parse(forwards[i].Source)
			if err != nil {
				return err
			}
		} else {
			src = &url.URL{
				Scheme: "unix",
				Path:   forwards[i].Source,
			}
		}

		forwardConfig := forwards[i]
		g.Go(func() error {
			defer os.Remove(forwardConfig.Source)
			forward, err := CreateSSHForward(ctx, src, forwardConfig.Destination, forwardConfig.Identity, dialer)
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
				if err := forward.AcceptAndTunnel(ctx); err != nil {
					logrus.Debugf("Error occurred handling ssh forwarded connection: %q", err)
				}
			}
			return nil
		})
	}

	return nil
}
