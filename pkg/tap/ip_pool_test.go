package tap

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIPPool(t *testing.T) {
	pool, err := NewIPPool("10.0.0.0/8")
	require.NoError(t, err)

	ip1, err := pool.GetOrAssign("mac1")
	assert.NoError(t, err)
	assert.Equal(t, "10.0.0.1", ip1.String())

	ip1, err = pool.GetOrAssign("mac1")
	assert.NoError(t, err)
	assert.Equal(t, "10.0.0.1", ip1.String())

	ip2, err := pool.GetOrAssign("mac2")
	assert.NoError(t, err)
	assert.Equal(t, "10.0.0.2", ip2.String())

	assert.Equal(t, map[string]string{"10.0.0.1": "mac1", "10.0.0.2": "mac2"}, pool.Leases())

	pool.Release("mac1")

	assert.Equal(t, map[string]string{"10.0.0.2": "mac2"}, pool.Leases())

	ip3, err := pool.GetOrAssign("mac3")
	assert.NoError(t, err)
	assert.Equal(t, "10.0.0.1", ip3.String())

	ip4, err := pool.GetOrAssign("mac4")
	assert.NoError(t, err)
	assert.Equal(t, "10.0.0.3", ip4.String())

	assert.Equal(t, map[string]string{"10.0.0.1": "mac3", "10.0.0.2": "mac2", "10.0.0.3": "mac4"}, pool.Leases())
}

func TestIPPoolExhaustion(t *testing.T) {
	// /30 subnet has only 4 IPs: network, 2 usable hosts, broadcast
	// After skipping network address, we have 3 assignable IPs
	pool, err := NewIPPool("192.168.1.0/30")
	require.NoError(t, err)

	// Assign all available IPs
	ip1, err := pool.GetOrAssign("mac1")
	assert.NoError(t, err)
	assert.Equal(t, "192.168.1.1", ip1.String())

	ip2, err := pool.GetOrAssign("mac2")
	assert.NoError(t, err)
	assert.Equal(t, "192.168.1.2", ip2.String())

	ip3, err := pool.GetOrAssign("mac3")
	assert.NoError(t, err)
	assert.Equal(t, "192.168.1.3", ip3.String())

	// Pool should be exhausted now
	_, err = pool.GetOrAssign("mac4")
	assert.Error(t, err)
	assert.Equal(t, "cannot find available IP", err.Error())
}

func TestIPPoolReserve(t *testing.T) {
	pool, err := NewIPPool("192.168.100.0/24")
	require.NoError(t, err)

	// Reserve specific IPs
	err = pool.Reserve("192.168.100.1", "gateway")
	require.NoError(t, err)

	err = pool.Reserve("192.168.100.10", "static-host")
	require.NoError(t, err)

	// Verify reservations are in leases
	leases := pool.Leases()
	assert.Equal(t, "gateway", leases["192.168.100.1"])
	assert.Equal(t, "static-host", leases["192.168.100.10"])

	// GetOrAssign should skip reserved IPs
	ip1, err := pool.GetOrAssign("mac1")
	assert.NoError(t, err)
	assert.NotEqual(t, "192.168.100.1", ip1.String())
	assert.NotEqual(t, "192.168.100.10", ip1.String())
	assert.Equal(t, "192.168.100.2", ip1.String()) // First available after .1

	// Requesting the same MAC that was used for reservation should return the reserved IP
	ip2, err := pool.GetOrAssign("gateway")
	assert.NoError(t, err)
	assert.Equal(t, "192.168.100.1", ip2.String())
}

func TestIPPoolMask(t *testing.T) {
	tests := []struct {
		cidr         string
		expectedBits int
	}{
		{"10.0.0.0/8", 8},
		{"172.16.0.0/16", 16},
		{"192.168.1.0/24", 24},
		{"192.168.1.0/30", 30},
	}

	for _, tt := range tests {
		pool, err := NewIPPool(tt.cidr)
		require.NoError(t, err)
		assert.Equal(t, tt.expectedBits, pool.Mask(), "Mask for %s", tt.cidr)
	}
}

func TestIPPoolReleaseNonExistent(t *testing.T) {
	pool, err := NewIPPool("10.0.0.0/24")
	require.NoError(t, err)

	ip1, err := pool.GetOrAssign("mac1")
	assert.NoError(t, err)
	assert.Equal(t, "10.0.0.1", ip1.String())

	// Release a MAC that doesn't exist should not panic
	pool.Release("nonexistent-mac")

	// Original lease should still be there
	assert.Equal(t, map[string]string{"10.0.0.1": "mac1"}, pool.Leases())
}

func TestIPPoolSmallSubnet(t *testing.T) {
	// /29 subnet has 8 IPs total: network + 6 usable + broadcast
	// After skipping network address (.0), we have 7 assignable IPs (.1 through .7)
	pool, err := NewIPPool("172.16.0.0/29")
	require.NoError(t, err)

	expectedIPs := []string{
		"172.16.0.1",
		"172.16.0.2",
		"172.16.0.3",
		"172.16.0.4",
		"172.16.0.5",
		"172.16.0.6",
		"172.16.0.7",
	}

	for i, expected := range expectedIPs {
		ip, err := pool.GetOrAssign("mac" + string(rune('1'+i)))
		assert.NoError(t, err)
		assert.Equal(t, expected, ip.String())
	}

	// Next assignment should fail
	_, err = pool.GetOrAssign("mac-extra")
	assert.Error(t, err)
	assert.Equal(t, "cannot find available IP", err.Error())
}

func TestIPPoolReleaseAndReassign(t *testing.T) {
	pool, err := NewIPPool("192.168.50.0/29")
	require.NoError(t, err)

	// Assign IPs
	ip1, _ := pool.GetOrAssign("mac1")
	ip2, _ := pool.GetOrAssign("mac2")
	ip3, _ := pool.GetOrAssign("mac3")

	assert.Equal(t, "192.168.50.1", ip1.String())
	assert.Equal(t, "192.168.50.2", ip2.String())
	assert.Equal(t, "192.168.50.3", ip3.String())

	// Release middle one
	pool.Release("mac2")

	// Next assignment should reuse the released IP
	ip4, err := pool.GetOrAssign("mac4")
	assert.NoError(t, err)
	assert.Equal(t, "192.168.50.2", ip4.String())

	// Verify final state
	expected := map[string]string{
		"192.168.50.1": "mac1",
		"192.168.50.2": "mac4",
		"192.168.50.3": "mac3",
	}
	assert.Equal(t, expected, pool.Leases())
}

func TestIPPoolInvalidSubnet(t *testing.T) {
	_, err := NewIPPool("invalid")
	assert.Error(t, err)

	_, err = NewIPPool("10.0.0.0")
	assert.Error(t, err)

	_, err = NewIPPool("10.0.0.0/99")
	assert.Error(t, err)
}

func TestIPPoolReserveInvalidIP(t *testing.T) {
	pool, err := NewIPPool("192.168.1.0/24")
	require.NoError(t, err)

	err = pool.Reserve("invalid-ip", "mac1")
	assert.Error(t, err)

	err = pool.Reserve("not-an-ip", "mac2")
	assert.Error(t, err)
}
