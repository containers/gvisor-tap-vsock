package tap

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIPPool(t *testing.T) {
	_, network, _ := net.ParseCIDR("10.0.0.0/8")
	pool := NewIPPool(network)

	ip1, err := pool.Assign(1)
	assert.NoError(t, err)
	assert.Equal(t, "10.0.0.1", ip1.String())

	ip2, err := pool.Assign(2)
	assert.NoError(t, err)
	assert.Equal(t, "10.0.0.2", ip2.String())

	assert.Equal(t, map[string]int{"10.0.0.1": 1, "10.0.0.2": 2}, pool.Leases())

	pool.Release(1)

	assert.Equal(t, map[string]int{"10.0.0.2": 2}, pool.Leases())

	ip3, err := pool.Assign(3)
	assert.NoError(t, err)
	assert.Equal(t, "10.0.0.1", ip3.String())

	ip4, err := pool.Assign(4)
	assert.NoError(t, err)
	assert.Equal(t, "10.0.0.3", ip4.String())

	assert.Equal(t, map[string]int{"10.0.0.1": 3, "10.0.0.2": 2, "10.0.0.3": 4}, pool.Leases())
}
