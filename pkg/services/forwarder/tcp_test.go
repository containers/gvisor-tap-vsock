package forwarder

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
)

func TestTCPRoutingAction(t *testing.T) {
	gateway := tcpip.AddrFrom4([4]byte{192, 168, 1, 1})
	other := tcpip.AddrFrom4([4]byte{8, 8, 8, 8})

	tests := []struct {
		name             string
		localAddress     tcpip.Address
		localPort        uint16
		blockAllOutbound bool
		allowlistActive  bool
		expected         tcpAction
	}{
		// --- No filtering (baseline) ---
		{
			name:             "NoFiltering",
			localAddress:     other,
			localPort:        80,
			blockAllOutbound: false,
			allowlistActive:  false,
			expected:         tcpDirect,
		},
		{
			name:             "NoFilteringPort443",
			localAddress:     other,
			localPort:        443,
			blockAllOutbound: false,
			allowlistActive:  false,
			expected:         tcpDirect,
		},

		// --- blockAllOutbound: normal cases ---
		{
			name:             "BlockAllOutbound",
			localAddress:     other,
			localPort:        80,
			blockAllOutbound: true,
			allowlistActive:  false,
			expected:         tcpBlock,
		},
		{
			name:             "BlockAllOutboundPort443",
			localAddress:     other,
			localPort:        443,
			blockAllOutbound: true,
			allowlistActive:  false,
			expected:         tcpBlock,
		},

		// --- blockAllOutbound: overrides allowlist ---
		{
			name:             "BlockAllOutboundOverridesAllow",
			localAddress:     other,
			localPort:        443,
			blockAllOutbound: true,
			allowlistActive:  true,
			expected:         tcpBlock,
		},
		{
			name:             "BlockAllOutboundOverridesAllowNon443",
			localAddress:     other,
			localPort:        80,
			blockAllOutbound: true,
			allowlistActive:  true,
			expected:         tcpBlock,
		},

		// --- blockAllOutbound: blocks even gateway ---
		{
			name:             "BlockAllOutboundBlocksGateway",
			localAddress:     gateway,
			localPort:        80,
			blockAllOutbound: true,
			allowlistActive:  false,
			expected:         tcpBlock,
		},
		{
			name:             "BlockAllOutboundBlocksGateway443",
			localAddress:     gateway,
			localPort:        443,
			blockAllOutbound: true,
			allowlistActive:  false,
			expected:         tcpBlock,
		},
		{
			name:             "BlockAllOutboundBlocksGatewayWithAllowlist",
			localAddress:     gateway,
			localPort:        443,
			blockAllOutbound: true,
			allowlistActive:  true,
			expected:         tcpBlock,
		},

		// --- blockAllOutbound: boundary ports ---
		{
			name:             "BlockAllOutboundPort0",
			localAddress:     other,
			localPort:        0,
			blockAllOutbound: true,
			allowlistActive:  false,
			expected:         tcpBlock,
		},
		{
			name:             "BlockAllOutboundPort65535",
			localAddress:     other,
			localPort:        65535,
			blockAllOutbound: true,
			allowlistActive:  false,
			expected:         tcpBlock,
		},
		{
			name:             "BlockAllOutboundPort1",
			localAddress:     other,
			localPort:        1,
			blockAllOutbound: true,
			allowlistActive:  false,
			expected:         tcpBlock,
		},

		// --- blockAllOutbound: special addresses ---
		{
			name:             "BlockAllOutboundLoopback",
			localAddress:     tcpip.AddrFrom4([4]byte{127, 0, 0, 1}),
			localPort:        80,
			blockAllOutbound: true,
			allowlistActive:  false,
			expected:         tcpBlock,
		},
		{
			name:             "BlockAllOutboundBroadcast",
			localAddress:     tcpip.AddrFrom4([4]byte{255, 255, 255, 255}),
			localPort:        80,
			blockAllOutbound: true,
			allowlistActive:  false,
			expected:         tcpBlock,
		},
		{
			name:             "BlockAllOutboundLinkLocal",
			localAddress:     tcpip.AddrFrom4([4]byte{169, 254, 169, 254}),
			localPort:        80,
			blockAllOutbound: true,
			allowlistActive:  false,
			expected:         tcpBlock,
		},
		{
			name:             "BlockAllOutboundZeroAddress",
			localAddress:     tcpip.AddrFrom4([4]byte{0, 0, 0, 0}),
			localPort:        80,
			blockAllOutbound: true,
			allowlistActive:  false,
			expected:         tcpBlock,
		},
		{
			name:             "BlockAllOutboundPrivateClassA",
			localAddress:     tcpip.AddrFrom4([4]byte{10, 0, 0, 1}),
			localPort:        443,
			blockAllOutbound: true,
			allowlistActive:  false,
			expected:         tcpBlock,
		},
		{
			name:             "BlockAllOutboundPrivateClassC",
			localAddress:     tcpip.AddrFrom4([4]byte{192, 168, 0, 1}),
			localPort:        443,
			blockAllOutbound: true,
			allowlistActive:  false,
			expected:         tcpBlock,
		},

		// --- blockAllOutbound: well-known ports ---
		{
			name:             "BlockAllOutboundDNS",
			localAddress:     other,
			localPort:        53,
			blockAllOutbound: true,
			allowlistActive:  false,
			expected:         tcpBlock,
		},
		{
			name:             "BlockAllOutboundSSH",
			localAddress:     other,
			localPort:        22,
			blockAllOutbound: true,
			allowlistActive:  false,
			expected:         tcpBlock,
		},
		{
			name:             "BlockAllOutboundHTTPS8443",
			localAddress:     other,
			localPort:        8443,
			blockAllOutbound: true,
			allowlistActive:  false,
			expected:         tcpBlock,
		},

		// --- blockAllOutbound: all exemptions combined, still blocks ---
		{
			name:             "BlockAllOutboundOverridesEverything",
			localAddress:     gateway,
			localPort:        443,
			blockAllOutbound: true,
			allowlistActive:  true,
			expected:         tcpBlock,
		},

		// --- Allowlist tests ---
		{
			name:             "AllowlistGateway",
			localAddress:     gateway,
			localPort:        80,
			blockAllOutbound: false,
			allowlistActive:  true,
			expected:         tcpDirect,
		},
		{
			name:             "AllowlistGatewayPort443",
			localAddress:     gateway,
			localPort:        443,
			blockAllOutbound: false,
			allowlistActive:  true,
			expected:         tcpDirect,
		},
		{
			name:             "AllowlistPort443",
			localAddress:     other,
			localPort:        443,
			blockAllOutbound: false,
			allowlistActive:  true,
			expected:         tcpTLSAllowlist,
		},
		{
			name:             "AllowlistNon443Blocked",
			localAddress:     other,
			localPort:        80,
			blockAllOutbound: false,
			allowlistActive:  true,
			expected:         tcpBlock,
		},
		{
			name:             "AllowlistPort8080Blocked",
			localAddress:     other,
			localPort:        8080,
			blockAllOutbound: false,
			allowlistActive:  true,
			expected:         tcpBlock,
		},
		{
			name:             "AllowlistPort22Blocked",
			localAddress:     other,
			localPort:        22,
			blockAllOutbound: false,
			allowlistActive:  true,
			expected:         tcpBlock,
		},

		// --- Allowlist: boundary ports ---
		{
			name:             "AllowlistPort0Blocked",
			localAddress:     other,
			localPort:        0,
			blockAllOutbound: false,
			allowlistActive:  true,
			expected:         tcpBlock,
		},
		{
			name:             "AllowlistPort65535Blocked",
			localAddress:     other,
			localPort:        65535,
			blockAllOutbound: false,
			allowlistActive:  true,
			expected:         tcpBlock,
		},
		{
			name:             "AllowlistPort1Blocked",
			localAddress:     other,
			localPort:        1,
			blockAllOutbound: false,
			allowlistActive:  true,
			expected:         tcpBlock,
		},
		{
			name:             "AllowlistPort442Blocked",
			localAddress:     other,
			localPort:        442,
			blockAllOutbound: false,
			allowlistActive:  true,
			expected:         tcpBlock,
		},
		{
			name:             "AllowlistPort444Blocked",
			localAddress:     other,
			localPort:        444,
			blockAllOutbound: false,
			allowlistActive:  true,
			expected:         tcpBlock,
		},

		// --- Allowlist: gateway with special ports ---
		{
			name:             "AllowlistGatewayPort0",
			localAddress:     gateway,
			localPort:        0,
			blockAllOutbound: false,
			allowlistActive:  true,
			expected:         tcpDirect,
		},
		{
			name:             "AllowlistGatewayPort65535",
			localAddress:     gateway,
			localPort:        65535,
			blockAllOutbound: false,
			allowlistActive:  true,
			expected:         tcpDirect,
		},

		// --- No filtering: boundary ports ---
		{
			name:             "NoFilteringPort0",
			localAddress:     other,
			localPort:        0,
			blockAllOutbound: false,
			allowlistActive:  false,
			expected:         tcpDirect,
		},
		{
			name:             "NoFilteringPort65535",
			localAddress:     other,
			localPort:        65535,
			blockAllOutbound: false,
			allowlistActive:  false,
			expected:         tcpDirect,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tcpRoutingAction(tt.localAddress, tt.localPort,
				tt.blockAllOutbound, tt.allowlistActive, gateway)
			require.Equal(t, tt.expected, got)
		})
	}
}

// TestTCPBlockAllOutboundIsAbsolute verifies that blockAllOutbound blocks
// every possible combination of address and port — no exemptions exist.
func TestTCPBlockAllOutboundIsAbsolute(t *testing.T) {
	gateway := tcpip.AddrFrom4([4]byte{192, 168, 1, 1})

	addresses := []tcpip.Address{
		gateway,
		tcpip.AddrFrom4([4]byte{8, 8, 8, 8}),
		tcpip.AddrFrom4([4]byte{0, 0, 0, 0}),
		tcpip.AddrFrom4([4]byte{127, 0, 0, 1}),
		tcpip.AddrFrom4([4]byte{255, 255, 255, 255}),
		tcpip.AddrFrom4([4]byte{169, 254, 169, 254}),
		tcpip.AddrFrom4([4]byte{10, 0, 0, 1}),
		tcpip.AddrFrom4([4]byte{172, 16, 0, 1}),
		tcpip.AddrFrom4([4]byte{192, 168, 0, 1}),
	}
	ports := []uint16{0, 1, 22, 53, 80, 443, 444, 8080, 8443, 65535}

	for _, addr := range addresses {
		for _, port := range ports {
			for _, allowlist := range []bool{false, true} {
				action := tcpRoutingAction(addr, port, true, allowlist, gateway)
				require.Equal(t, tcpBlock, action,
					"blockAllOutbound must block addr=%s port=%d allowlist=%v",
					addr.String(), port, allowlist)
			}
		}
	}
}

// TestTCPNoFilteringAlwaysAllows verifies that with both blockAllOutbound=false
// and no allowlist, all traffic is forwarded regardless of address or port.
func TestTCPNoFilteringAlwaysAllows(t *testing.T) {
	gateway := tcpip.AddrFrom4([4]byte{192, 168, 1, 1})

	addresses := []tcpip.Address{
		gateway,
		tcpip.AddrFrom4([4]byte{8, 8, 8, 8}),
		tcpip.AddrFrom4([4]byte{0, 0, 0, 0}),
		tcpip.AddrFrom4([4]byte{127, 0, 0, 1}),
		tcpip.AddrFrom4([4]byte{255, 255, 255, 255}),
	}
	ports := []uint16{0, 1, 22, 53, 80, 443, 8080, 65535}

	for _, addr := range addresses {
		for _, port := range ports {
			action := tcpRoutingAction(addr, port, false, false, gateway)
			require.Equal(t, tcpDirect, action,
				"no filtering must allow addr=%s port=%d",
				addr.String(), port)
		}
	}
}

// TestTCPAllowlistOnly443PassesTLS verifies that when the allowlist is active
// (without blockAllOutbound), only port 443 to non-gateway addresses gets
// TLS inspection — every other port is blocked.
func TestTCPAllowlistOnly443PassesTLS(t *testing.T) {
	gateway := tcpip.AddrFrom4([4]byte{192, 168, 1, 1})
	other := tcpip.AddrFrom4([4]byte{8, 8, 8, 8})

	blockedPorts := []uint16{0, 1, 22, 53, 80, 442, 444, 8080, 8443, 65535}
	for _, port := range blockedPorts {
		action := tcpRoutingAction(other, port, false, true, gateway)
		require.Equal(t, tcpBlock, action,
			"allowlist must block non-443 port=%d", port)
	}

	action := tcpRoutingAction(other, 443, false, true, gateway)
	require.Equal(t, tcpTLSAllowlist, action,
		"allowlist must TLS-inspect port 443")
}

// TestTCPAllowlistGatewayAlwaysExempt verifies that the gateway address
// bypasses the allowlist on any port.
func TestTCPAllowlistGatewayAlwaysExempt(t *testing.T) {
	gateway := tcpip.AddrFrom4([4]byte{192, 168, 1, 1})

	ports := []uint16{0, 1, 22, 53, 80, 443, 8080, 65535}
	for _, port := range ports {
		action := tcpRoutingAction(gateway, port, false, true, gateway)
		require.Equal(t, tcpDirect, action,
			"gateway must be exempt on port=%d", port)
	}
}

// TestTCPRoutingActionZeroGateway verifies behavior when no gateway IP is
// configured (zero-value address). No address should match the gateway
// exemption, so all allowlist traffic is filtered normally.
func TestTCPRoutingActionZeroGateway(t *testing.T) {
	var zeroGateway tcpip.Address
	other := tcpip.AddrFrom4([4]byte{8, 8, 8, 8})

	// Port 443 goes to TLS inspection (not exempted as gateway)
	action := tcpRoutingAction(other, 443, false, true, zeroGateway)
	require.Equal(t, tcpTLSAllowlist, action)

	// Non-443 is blocked
	action = tcpRoutingAction(other, 80, false, true, zeroGateway)
	require.Equal(t, tcpBlock, action)

	// Zero address to zero gateway — technically matches, gets exempted
	action = tcpRoutingAction(zeroGateway, 80, false, true, zeroGateway)
	require.Equal(t, tcpDirect, action)

	// blockAllOutbound still blocks everything
	action = tcpRoutingAction(other, 443, true, true, zeroGateway)
	require.Equal(t, tcpBlock, action)
}

// ---------------------------------------------------------------------------
// SNI matches destination (DNS cross-check pure function)
// ---------------------------------------------------------------------------

func TestSNIMatchesDestination_ExactMatch(t *testing.T) {
	dest := tcpip.AddrFrom4([4]byte{1, 2, 3, 4})
	resolved := []net.IPAddr{{IP: net.ParseIP("1.2.3.4")}}
	require.True(t, sniMatchesDestination(dest, resolved))
}

func TestSNIMatchesDestination_NoMatch(t *testing.T) {
	dest := tcpip.AddrFrom4([4]byte{1, 2, 3, 4})
	resolved := []net.IPAddr{{IP: net.ParseIP("5.6.7.8")}}
	require.False(t, sniMatchesDestination(dest, resolved))
}

func TestSNIMatchesDestination_MultipleIPs(t *testing.T) {
	dest := tcpip.AddrFrom4([4]byte{10, 0, 0, 1})
	resolved := []net.IPAddr{
		{IP: net.ParseIP("5.6.7.8")},
		{IP: net.ParseIP("10.0.0.1")},
		{IP: net.ParseIP("192.168.1.1")},
	}
	require.True(t, sniMatchesDestination(dest, resolved),
		"should match when any resolved IP matches destination")
}

func TestSNIMatchesDestination_EmptyResolved(t *testing.T) {
	dest := tcpip.AddrFrom4([4]byte{1, 2, 3, 4})
	require.False(t, sniMatchesDestination(dest, nil))
	require.False(t, sniMatchesDestination(dest, []net.IPAddr{}))
}
