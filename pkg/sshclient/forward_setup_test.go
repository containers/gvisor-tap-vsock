package sshclient

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"testing"

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
