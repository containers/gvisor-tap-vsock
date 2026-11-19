package transport

import (
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListenAddrTCP(t *testing.T) {
	t.Run("succeeds on a free port", func(t *testing.T) {
		ln, err := ListenAddr("tcp", ":0")
		require.NoError(t, err)
		require.NoError(t, ln.Close())
	})

	// The other socket plays the role of e.g. vmware-hostd listening on
	// 0.0.0.0:443 while we listen on the dual-stack ":443".
	for _, otherAddr := range []string{"0.0.0.0:0", "127.0.0.1:0"} {
		t.Run("fails when "+otherAddr+" is in use", func(t *testing.T) {
			other, err := net.Listen("tcp4", otherAddr)
			require.NoError(t, err)
			defer other.Close()
			port := other.Addr().(*net.TCPAddr).Port

			ln, err := ListenAddr("tcp", fmt.Sprintf(":%d", port))
			if err == nil {
				ln.Close()
			}
			assert.Error(t, err, "expected exclusive bind on :%d to fail while %s is in use", port, other.Addr())
		})
	}
}

func TestListenAddrUDP(t *testing.T) {
	other, err := net.ListenPacket("udp4", "0.0.0.0:0")
	require.NoError(t, err)
	defer other.Close()
	port := other.LocalAddr().(*net.UDPAddr).Port

	conn, err := ListenPacketAddr("udp", fmt.Sprintf(":%d", port))
	if err == nil {
		conn.Close()
	}
	assert.Error(t, err, "expected exclusive bind on :%d to fail while %s is in use", port, other.LocalAddr())
}
