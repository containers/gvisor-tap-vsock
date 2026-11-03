package dns

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func writeResolvConf(t *testing.T, path, contents string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
}

func TestResolvConfFollowsChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	writeResolvConf(t, path, "nameserver 192.0.2.1\n")
	r := newResolvConf(path)
	require.Equal(t, []string{"192.0.2.1:53"}, r.nameservers())

	// The host switched DNS servers, e.g. after disconnecting from a VPN.
	writeResolvConf(t, path, "search example.org\nnameserver 192.0.2.2\nnameserver 2001:db8::2\nnameserver fe80::1%en0\n")
	require.Equal(t, []string{"192.0.2.2:53", "[2001:db8::2]:53", "[fe80::1%en0]:53"}, r.nameservers())
}

func TestResolvConfFollowsSymlinkChanges(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks needs Developer Mode or admin rights on Windows")
	}
	// On macOS, /etc/resolv.conf is a symlink, and the file it points to
	// may be replaced rather than rewritten.
	dir := t.TempDir()
	writeResolvConf(t, filepath.Join(dir, "a.conf"), "nameserver 192.0.2.1\n")
	writeResolvConf(t, filepath.Join(dir, "b.conf"), "nameserver 192.0.2.2\n")
	link := filepath.Join(dir, "resolv.conf")
	require.NoError(t, os.Symlink("a.conf", link))
	r := newResolvConf(link)
	require.Equal(t, []string{"192.0.2.1:53"}, r.nameservers())

	newLink := filepath.Join(dir, "resolv.conf.new")
	require.NoError(t, os.Symlink("b.conf", newLink))
	require.NoError(t, os.Rename(newLink, link))
	require.Equal(t, []string{"192.0.2.2:53"}, r.nameservers())
}

func TestResolvConfRereadsOnlyChangedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	writeResolvConf(t, path, "nameserver 192.0.2.1\n")
	changed := time.Now().Add(-time.Hour)
	require.NoError(t, os.Chtimes(path, time.Time{}, changed))
	r := newResolvConf(path)

	// Same file, size and modification time: the file is not read again.
	writeResolvConf(t, path, "nameserver 192.0.2.2\n")
	require.NoError(t, os.Chtimes(path, time.Time{}, changed))
	require.Equal(t, []string{"192.0.2.1:53"}, r.nameservers())

	// A new size or a new modification time: the file is read again.
	writeResolvConf(t, path, "nameserver 192.0.2.30\n")
	require.NoError(t, os.Chtimes(path, time.Time{}, changed))
	require.Equal(t, []string{"192.0.2.30:53"}, r.nameservers())
	writeResolvConf(t, path, "nameserver 192.0.2.40\n")
	require.NoError(t, os.Chtimes(path, time.Time{}, changed.Add(time.Second)))
	require.Equal(t, []string{"192.0.2.40:53"}, r.nameservers())
}

func TestResolvConfFollowsReplacedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	writeResolvConf(t, path, "nameserver 192.0.2.1\n")
	changed := time.Now().Add(-time.Hour)
	require.NoError(t, os.Chtimes(path, time.Time{}, changed))
	r := newResolvConf(path)

	// A new file is renamed into place, as tools that rewrite resolv.conf
	// atomically do. Even with the same size and modification time, it is
	// read.
	newPath := filepath.Join(dir, "resolv.conf.new")
	writeResolvConf(t, newPath, "nameserver 192.0.2.2\n")
	require.NoError(t, os.Chtimes(newPath, time.Time{}, changed))
	require.NoError(t, os.Rename(newPath, path))
	require.Equal(t, []string{"192.0.2.2:53"}, r.nameservers())
}

func TestResolvConfRereadsRecentlyChangedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	writeResolvConf(t, path, "nameserver 192.0.2.1\n")
	// Less than a second old whatever the speed of this test, since it is
	// in the future.
	changed := time.Now().Add(time.Hour)
	require.NoError(t, os.Chtimes(path, time.Time{}, changed))
	r := newResolvConf(path)

	// A second change in the same timestamp tick: same file, size and
	// modification time, but the file is read again.
	writeResolvConf(t, path, "nameserver 192.0.2.2\n")
	require.NoError(t, os.Chtimes(path, time.Time{}, changed))
	require.Equal(t, []string{"192.0.2.2:53"}, r.nameservers())
}

func TestResolvConfKeepsLastNameserversWhenUnusable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	writeResolvConf(t, path, "nameserver 192.0.2.1\n")
	r := newResolvConf(path)

	require.NoError(t, os.Remove(path))
	require.Equal(t, []string{"192.0.2.1:53"}, r.nameservers())

	// Contents seen while the file is being rewritten in place.
	writeResolvConf(t, path, "")
	require.Equal(t, []string{"192.0.2.1:53"}, r.nameservers())
	writeResolvConf(t, path, "nameserver 192.0")
	require.Equal(t, []string{"192.0.2.1:53"}, r.nameservers())

	writeResolvConf(t, path, "nameserver 192.0.2.2\n")
	require.Equal(t, []string{"192.0.2.2:53"}, r.nameservers())
}

func TestResolvConfWithoutNameservers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	require.Empty(t, newResolvConf(path).nameservers())

	writeResolvConf(t, path, "search example.org\n")
	require.Empty(t, newResolvConf(path).nameservers())
}

func TestResolvConfConcurrentRewrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	first := []string{"192.0.2.1:53"}
	second := []string{"192.0.2.2:53"}
	writeResolvConf(t, path, "nameserver 192.0.2.1\n")
	r := newResolvConf(path)

	var wg sync.WaitGroup
	results := make(chan []string, 800)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				results <- r.nameservers()
			}
		}()
	}
	for i := range 50 {
		if i%2 == 0 {
			writeResolvConf(t, path, "nameserver 192.0.2.2\n")
		} else {
			writeResolvConf(t, path, "nameserver 192.0.2.1\n")
		}
	}
	wg.Wait()
	close(results)

	// os.WriteFile truncates before writing, so readers may see an empty
	// file; they must still get one of the two complete lists.
	for servers := range results {
		require.Contains(t, [][]string{first, second}, servers)
	}
}
