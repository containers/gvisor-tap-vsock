package dns

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestHostsFile(t *testing.T) {
	hostsFile := filepath.Join(t.TempDir(), "hosts")
	assert.NoError(t, os.WriteFile(hostsFile, []byte(`127.0.0.1 entry1`), 0600))

	hosts, err := NewHostsFile(hostsFile)
	assert.NoError(t, err)
	ip, err := hosts.LookupByHostname("entry1")
	assert.NoError(t, err)
	assert.Equal(t, "127.0.0.1", ip.String())
}

func TestReloadingHostsFile(t *testing.T) {
	hostsFile := filepath.Join(t.TempDir(), "hosts")
	assert.NoError(t, os.WriteFile(hostsFile, []byte(`127.0.0.1   entry1`), 0600))

	hosts, err := NewHostsFile(hostsFile)
	time.Sleep(time.Second)
	assert.NoError(t, err)
	ip, err := hosts.LookupByHostname("entry1")
	assert.NoError(t, err)
	assert.Equal(t, "127.0.0.1", ip.String())

	assert.NoError(t, os.WriteFile(hostsFile, []byte(`127.0.0.1   entry2 foobar`), 0600))
	time.Sleep(time.Second)

	ipBar, err := hosts.LookupByHostname("foobar")
	assert.NoError(t, err)
	assert.Equal(t, "127.0.0.1", ipBar.String())

}
