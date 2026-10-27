package sshclient

import (
	"context"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sync/errgroup"
)

// socketTempDir returns a temporary directory with a short path: unix
// socket paths are limited to about 100 characters, which the directories
// returned by t.TempDir() can exceed on Windows and macOS.
func socketTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "sshclient")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("failed to remove %s: %v", dir, err)
		}
	})
	return dir
}

// unixSocketURL returns the unix:// URL for path. Windows paths ("C:\...")
// get a leading "/", which transport.UnixSocketPath() strips.
func unixSocketURL(path string) string {
	path = filepath.ToSlash(path)
	if path[0] != '/' {
		path = "/" + path
	}
	return (&url.URL{Scheme: "unix", Path: path}).String()
}

// closeTrackingDialer is an SSHDialer handing out net.Pipe() connections
// and recording them, so that tests can check they all got closed.
type closeTrackingDialer struct {
	dialOnce sync.Once
	dialed   chan struct{}

	mu    sync.Mutex
	conns []*trackedConn
}

func newCloseTrackingDialer() *closeTrackingDialer {
	return &closeTrackingDialer{dialed: make(chan struct{})}
}

func (d *closeTrackingDialer) DialContextTCP(_ context.Context, _ string) (net.Conn, error) {
	d.dialOnce.Do(func() { close(d.dialed) })
	_, conn := net.Pipe()
	tracked := &trackedConn{Conn: conn}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.conns = append(d.conns, tracked)
	return tracked, nil
}

func (d *closeTrackingDialer) trackedConns() []*trackedConn {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.conns
}

type trackedConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *trackedConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

// createStaleSocket leaves a unix socket file behind at path, as a
// crashed process would.
func createStaleSocket(t *testing.T, path string) {
	t.Helper()
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	listener.(*net.UnixListener).SetUnlinkOnClose(false)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("failed to leave a stale socket behind: %v", err)
	}
}

func TestSetupForwardsKeepsUnixSocketOnSetupFailure(t *testing.T) {
	for _, asURL := range []bool{false, true} {
		name := "path"
		if asURL {
			name = "URL"
		}
		t.Run(name, func(t *testing.T) {
			socketPath := filepath.Join(socketTempDir(t), "forward.sock")
			if err := os.WriteFile(socketPath, []byte("existing file"), 0o600); err != nil {
				t.Fatal(err)
			}

			source := socketPath
			if asURL {
				source = unixSocketURL(socketPath)
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var g errgroup.Group
			err := SetupForwards(ctx, &g, []ForwardConfig{{
				Source:      source,
				Destination: &url.URL{Scheme: "ssh", Host: "127.0.0.1:1", Path: "/forwarded-socket"},
			}}, nil)
			if err != nil {
				t.Fatalf("SetupForwards() error = %v", err)
			}
			cancel()
			if err := g.Wait(); err == nil {
				t.Fatal("expected SSH forward setup to fail")
			}

			if _, err := os.Stat(socketPath); err != nil {
				t.Errorf("pre-existing file was removed on setup failure; stat error = %v", err)
			}
		})
	}
}

func TestSetupForwardsRemovesStaleUnixSocket(t *testing.T) {
	for _, asURL := range []bool{false, true} {
		name := "path"
		if asURL {
			name = "URL"
		}
		t.Run(name, func(t *testing.T) {
			socketPath := filepath.Join(socketTempDir(t), "forward.sock")
			createStaleSocket(t, socketPath)
			stale, err := os.Stat(socketPath)
			if err != nil {
				t.Fatal(err)
			}

			source := socketPath
			if asURL {
				source = unixSocketURL(socketPath)
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var g errgroup.Group
			// Nothing listens on the destination, so the SSH forward
			// setup is expected to fail once past the socket listening.
			err = SetupForwards(ctx, &g, []ForwardConfig{{
				Source:      source,
				Destination: &url.URL{Scheme: "ssh", Host: "127.0.0.1:1", Path: "/forwarded-socket"},
			}}, nil)
			if err != nil {
				t.Fatalf("SetupForwards() error = %v", err)
			}
			cancel()
			if err := g.Wait(); err == nil {
				t.Fatal("expected SSH forward setup to fail")
			}

			// The stale socket must have been replaced by the one the
			// forward listened on (or be gone altogether); the setup only
			// got past net.Listen() because the stale one was removed.
			current, err := os.Stat(socketPath)
			if err == nil && os.SameFile(stale, current) {
				t.Errorf("stale socket was not removed before listening")
			}
		})
	}
}

func TestSetupForwardsClosesListenerOnSetupFailure(t *testing.T) {
	socketPath := filepath.Join(socketTempDir(t), "forward.sock")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var g errgroup.Group
	// Nothing listens on the destination, so the SSH forward setup fails
	// once the socket is being listened on.
	err := SetupForwards(ctx, &g, []ForwardConfig{{
		Source:      socketPath,
		Destination: &url.URL{Scheme: "ssh", Host: "127.0.0.1:1", Path: "/forwarded-socket"},
	}}, nil)
	if err != nil {
		t.Fatalf("SetupForwards() error = %v", err)
	}
	cancel()
	if err := g.Wait(); err == nil {
		t.Fatal("expected SSH forward setup to fail")
	}

	// The listener setupProxy() created must be closed on failure, which
	// also removes the unix socket file (net.Listen() only unlinks it on
	// Close()), rather than being leaked until process exit.
	if _, err := os.Stat(socketPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("socket file still exists after setup failure; stat error = %v", err)
	}
}

func TestSetupForwardsClosesConnOnBastionSetupFailure(t *testing.T) {
	// The identity cannot be parsed, so CreateBastion() fails before the
	// SSH handshake; the connection it was given must then be closed by
	// its caller.
	identity := filepath.Join(t.TempDir(), "identity")
	if err := os.WriteFile(identity, []byte("not an ssh key"), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dialer := newCloseTrackingDialer()

	var g errgroup.Group
	err := SetupForwards(ctx, &g, []ForwardConfig{{
		Source:      filepath.Join(socketTempDir(t), "forward.sock"),
		Destination: &url.URL{Scheme: "ssh", User: url.User("root"), Host: "127.0.0.1:1", Path: "/forwarded-socket"},
		Identity:    identity,
	}}, dialer)
	if err != nil {
		t.Fatalf("SetupForwards() error = %v", err)
	}

	// Wait for the first connection to the bastion before cancelling,
	// the forward setup would otherwise give up before dialing anything.
	select {
	case <-dialer.dialed:
	case <-time.After(5 * time.Second):
		t.Fatal("the forward never dialed the bastion")
	}
	cancel()
	if err := g.Wait(); err == nil {
		t.Fatal("expected SSH forward setup to fail")
	}

	for i, conn := range dialer.trackedConns() {
		if !conn.closed.Load() {
			t.Errorf("connection %d to the bastion was leaked", i)
		}
	}
}

func TestRemoveStaleSocket(t *testing.T) {
	dir := socketTempDir(t)

	// A leftover socket file is removed
	socketPath := filepath.Join(dir, "stale.sock")
	createStaleSocket(t, socketPath)
	if err := removeStaleSocket(socketPath); err != nil {
		t.Fatalf("removeStaleSocket() error = %v", err)
	}
	if _, err := os.Stat(socketPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stale socket still exists; stat error = %v", err)
	}

	// A socket still being listened on is left untouched
	activePath := filepath.Join(dir, "active.sock")
	listener, err := net.Listen("unix", activePath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := removeStaleSocket(activePath); err != nil {
		t.Fatalf("removeStaleSocket() error = %v", err)
	}
	if _, err := os.Stat(activePath); err != nil {
		t.Errorf("active socket was removed; stat error = %v", err)
	}

	// A regular file is left untouched
	filePath := filepath.Join(dir, "regular.file")
	if err := os.WriteFile(filePath, []byte("existing file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeStaleSocket(filePath); err != nil {
		t.Fatalf("removeStaleSocket() error = %v", err)
	}
	if _, err := os.Stat(filePath); err != nil {
		t.Errorf("regular file was removed; stat error = %v", err)
	}

	// A missing file is not an error
	if err := removeStaleSocket(filepath.Join(dir, "nonexistent")); err != nil {
		t.Fatalf("removeStaleSocket() error = %v", err)
	}
}

func TestSetupForwardsReturnsInvalidSocketURL(t *testing.T) {
	var g errgroup.Group
	err := SetupForwards(context.Background(), &g, []ForwardConfig{{
		Source: "unix://[::1",
	}}, nil)
	if err == nil {
		t.Fatal("expected invalid socket URL to fail")
	}
}

func TestSetupForwardsRejectsUnsupportedSocketURLScheme(t *testing.T) {
	var g errgroup.Group
	if err := SetupForwards(context.Background(), &g, []ForwardConfig{{
		Source: "tcp://127.0.0.1:1234",
	}}, nil); err != nil {
		t.Fatalf("SetupForwards() error = %v", err)
	}
	if err := g.Wait(); err == nil {
		t.Fatal("expected unsupported socket URL scheme to fail")
	}
}

func TestParseForwardSource(t *testing.T) {
	tests := []struct {
		name       string
		source     string
		wantScheme string
		wantHost   string
		wantPath   string
	}{
		{
			name:       "unix path",
			source:     "/tmp/forward.sock",
			wantScheme: "unix",
			wantPath:   "/tmp/forward.sock",
		},
		{
			name:       "unix URL",
			source:     "unix:///tmp/forward.sock",
			wantScheme: "unix",
			wantPath:   "/tmp/forward.sock",
		},
		{
			name:       "npipe URL",
			source:     "npipe:////./pipe/gvproxy",
			wantScheme: "npipe",
			wantPath:   "//./pipe/gvproxy",
		},
		{
			name:       "other URL",
			source:     "tcp://127.0.0.1:1234",
			wantScheme: "tcp",
			wantHost:   "127.0.0.1:1234",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseForwardSource(tt.source)
			if err != nil {
				t.Fatalf("parseForwardSource() error = %v", err)
			}
			if got.Scheme != tt.wantScheme || got.Host != tt.wantHost || got.Path != tt.wantPath {
				t.Errorf("parseForwardSource() = %q, want scheme=%q host=%q path=%q", got, tt.wantScheme, tt.wantHost, tt.wantPath)
			}
		})
	}
}
