package transport

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnixSocketPath(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		rawURL   string
		goos     string
		wantPath string
	}{
		{
			name:     "Unix absolute path on linux",
			rawURL:   "unix:///tmp/notification.sock",
			goos:     "linux",
			wantPath: "/tmp/notification.sock",
		},
		{
			name:     "Unix absolute path on darwin",
			rawURL:   "unix:///var/run/gvproxy.sock",
			goos:     "darwin",
			wantPath: "/var/run/gvproxy.sock",
		},
		{
			name:     "Unix absolute path on windows is unchanged",
			rawURL:   "unix:///tmp/notification.sock",
			goos:     "windows",
			wantPath: "/tmp/notification.sock",
		},
		{
			name:     "Windows drive letter (three slashes)",
			rawURL:   "unix:///c:/Users/foo/notification.sock",
			goos:     "windows",
			wantPath: "c:/Users/foo/notification.sock",
		},
		{
			name:     "Windows drive letter nested path",
			rawURL:   "unix:///d:/ProgramData/gvproxy/default.sock",
			goos:     "windows",
			wantPath: "d:/ProgramData/gvproxy/default.sock",
		},
		{
			name:     "Windows drive letter not trimmed on linux",
			rawURL:   "unix:///c:/Users/foo/notification.sock",
			goos:     "linux",
			wantPath: "/c:/Users/foo/notification.sock",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u, err := url.Parse(tc.rawURL)
			require.NoError(t, err)
			got := UnixSocketPath(u, tc.goos)
			assert.Equal(t, tc.wantPath, got)
		})
	}
}
