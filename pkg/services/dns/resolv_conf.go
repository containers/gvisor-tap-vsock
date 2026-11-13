package dns

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

var errNoNameservers = errors.New("no valid nameserver line")

// recentChange is how long after a change the file is read on every use. A
// second change within the file system's timestamp granularity (a second on
// some file systems) can leave its size and modification time unchanged.
const recentChange = time.Second

// resolvConf provides the DNS servers listed in a resolv.conf file.
//
// The file is read again when it changes, so that forwarded queries follow
// host DNS changes, such as disconnecting from a VPN or switching networks,
// without restarting gvproxy. Much like glibc before each lookup, each use
// stats the file and parses it again only if its size or modification time
// changed, it was replaced, or it changed less than recentChange ago. This
// needs no file watcher, which caused problems on macOS in the past (see
// #462).
type resolvConf struct {
	path string

	mu         sync.Mutex
	servers    []string
	readFailed bool
	// readFrom describes the file as it was when servers was last read, or
	// is nil if the file must be read again on the next use.
	readFrom os.FileInfo
}

func newResolvConf(path string) *resolvConf {
	r := &resolvConf{path: path}
	// Read the file once now so that the servers, or a problem reading
	// them, are logged at startup.
	r.nameservers()
	return r
}

// nameservers returns the DNS servers ("ip:port") currently listed in the
// file. If the file cannot be read or lists no valid server, for example
// while it is being rewritten, the servers from the last successful read are
// returned. The returned slice must not be modified.
func (r *resolvConf) nameservers() []string {
	current, statErr := os.Stat(r.path)

	r.mu.Lock()
	if statErr == nil && r.readFrom != nil && sameFileVersion(r.readFrom, current) {
		servers := r.servers
		r.mu.Unlock()
		return servers
	}
	r.mu.Unlock()

	// Read outside the lock so that queries are not serialized on file I/O.
	servers, readFrom, err := readNameservers(r.path)

	r.mu.Lock()
	defer r.mu.Unlock()

	// Skip the next read only if the next change will show in the size or
	// modification time of the file that was read.
	r.readFrom = nil
	if err == nil && time.Since(readFrom.ModTime()) > recentChange {
		r.readFrom = readFrom
	}

	if err != nil {
		if !r.readFailed {
			r.readFailed = true
			if len(r.servers) == 0 {
				log.Warnf("no DNS servers found in %s, DNS queries for SOA/PTR and other unhandled types will not be forwarded: %v", r.path, err)
			} else {
				log.Warnf("no DNS servers found in %s, DNS queries for SOA/PTR and other unhandled types are still forwarded to %v: %v", r.path, r.servers, err)
			}
		}
		return r.servers
	}

	if r.readFailed || !slices.Equal(servers, r.servers) {
		log.Infof("using DNS servers %v from %s for SOA/PTR and other unhandled query types", servers, r.path)
		r.servers = servers
	}
	r.readFailed = false
	return r.servers
}

// sameFileVersion reports whether a and b describe the same file with the
// same size and modification time.
func sameFileVersion(a, b os.FileInfo) bool {
	return os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

// readNameservers returns the DNS servers listed in the file at path, and
// the file's details as it was opened.
func readNameservers(path string) ([]string, os.FileInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	conf, err := dns.ClientConfigFromReader(f)
	if err != nil {
		return nil, nil, err
	}
	servers := make([]string, 0, len(conf.Servers))
	for _, s := range conf.Servers {
		// Skip anything that is not an IP address, such as a line cut
		// short by a rewrite in progress. ParseAddr accepts the zone of
		// link-local IPv6 servers ("fe80::1%en0").
		if _, err := netip.ParseAddr(s); err != nil {
			continue
		}
		servers = append(servers, net.JoinHostPort(s, conf.Port))
	}
	if len(servers) == 0 {
		return nil, nil, errNoNameservers
	}
	return servers, fi, nil
}
