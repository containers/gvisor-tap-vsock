package forwarder

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
)

func TestUDPRoutingAction(t *testing.T) {
	gateway := tcpip.AddrFrom4([4]byte{192, 168, 1, 1})
	other := tcpip.AddrFrom4([4]byte{8, 8, 8, 8})

	tests := []struct {
		name             string
		localAddress     tcpip.Address
		blockAllOutbound bool
		allowlistActive  bool
		expected         udpAction
	}{
		// --- No filtering (baseline) ---
		{
			name:             "NoFiltering",
			localAddress:     other,
			blockAllOutbound: false,
			allowlistActive:  false,
			expected:         udpDirect,
		},
		{
			name:             "NoFilteringGateway",
			localAddress:     gateway,
			blockAllOutbound: false,
			allowlistActive:  false,
			expected:         udpDirect,
		},

		// --- blockAllOutbound: normal cases ---
		{
			name:             "BlockAllOutbound",
			localAddress:     other,
			blockAllOutbound: true,
			allowlistActive:  false,
			expected:         udpBlock,
		},

		// --- blockAllOutbound: overrides allowlist ---
		{
			name:             "BlockAllOverridesAllow",
			localAddress:     other,
			blockAllOutbound: true,
			allowlistActive:  true,
			expected:         udpBlock,
		},

		// --- blockAllOutbound: blocks even gateway ---
		{
			name:             "BlockAllOutboundBlocksGateway",
			localAddress:     gateway,
			blockAllOutbound: true,
			allowlistActive:  false,
			expected:         udpBlock,
		},
		{
			name:             "BlockAllOutboundBlocksGatewayWithAllowlist",
			localAddress:     gateway,
			blockAllOutbound: true,
			allowlistActive:  true,
			expected:         udpBlock,
		},

		// --- blockAllOutbound: special addresses ---
		{
			name:             "BlockAllOutboundLoopback",
			localAddress:     tcpip.AddrFrom4([4]byte{127, 0, 0, 1}),
			blockAllOutbound: true,
			allowlistActive:  false,
			expected:         udpBlock,
		},
		{
			name:             "BlockAllOutboundBroadcast",
			localAddress:     tcpip.AddrFrom4([4]byte{255, 255, 255, 255}),
			blockAllOutbound: true,
			allowlistActive:  false,
			expected:         udpBlock,
		},
		{
			name:             "BlockAllOutboundLinkLocal",
			localAddress:     tcpip.AddrFrom4([4]byte{169, 254, 169, 254}),
			blockAllOutbound: true,
			allowlistActive:  false,
			expected:         udpBlock,
		},
		{
			name:             "BlockAllOutboundZeroAddress",
			localAddress:     tcpip.AddrFrom4([4]byte{0, 0, 0, 0}),
			blockAllOutbound: true,
			allowlistActive:  false,
			expected:         udpBlock,
		},
		{
			name:             "BlockAllOutboundPrivateClassA",
			localAddress:     tcpip.AddrFrom4([4]byte{10, 0, 0, 1}),
			blockAllOutbound: true,
			allowlistActive:  false,
			expected:         udpBlock,
		},
		{
			name:             "BlockAllOutboundPrivateClassC",
			localAddress:     tcpip.AddrFrom4([4]byte{192, 168, 0, 1}),
			blockAllOutbound: true,
			allowlistActive:  false,
			expected:         udpBlock,
		},

		// --- blockAllOutbound: all exemptions combined ---
		{
			name:             "BlockAllOutboundOverridesEverything",
			localAddress:     gateway,
			blockAllOutbound: true,
			allowlistActive:  true,
			expected:         udpBlock,
		},

		// --- Allowlist tests ---
		{
			name:             "AllowlistGateway",
			localAddress:     gateway,
			blockAllOutbound: false,
			allowlistActive:  true,
			expected:         udpDirect,
		},
		{
			name:             "AllowlistNonGateway",
			localAddress:     other,
			blockAllOutbound: false,
			allowlistActive:  true,
			expected:         udpBlock,
		},
		{
			name:             "AllowlistBlocksLoopback",
			localAddress:     tcpip.AddrFrom4([4]byte{127, 0, 0, 1}),
			blockAllOutbound: false,
			allowlistActive:  true,
			expected:         udpBlock,
		},
		{
			name:             "AllowlistBlocksPrivate",
			localAddress:     tcpip.AddrFrom4([4]byte{10, 0, 0, 1}),
			blockAllOutbound: false,
			allowlistActive:  true,
			expected:         udpBlock,
		},

		// --- No filtering: special addresses ---
		{
			name:             "NoFilteringLoopback",
			localAddress:     tcpip.AddrFrom4([4]byte{127, 0, 0, 1}),
			blockAllOutbound: false,
			allowlistActive:  false,
			expected:         udpDirect,
		},
		{
			name:             "NoFilteringZeroAddress",
			localAddress:     tcpip.AddrFrom4([4]byte{0, 0, 0, 0}),
			blockAllOutbound: false,
			allowlistActive:  false,
			expected:         udpDirect,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := udpRoutingAction(tt.localAddress, tt.blockAllOutbound, tt.allowlistActive, gateway)
			require.Equal(t, tt.expected, got)
		})
	}
}

// TestUDPBlockAllOutboundIsAbsolute verifies that blockAllOutbound blocks
// every possible address — no exemptions exist, not even the gateway.
func TestUDPBlockAllOutboundIsAbsolute(t *testing.T) {
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

	for _, addr := range addresses {
		for _, allowlist := range []bool{false, true} {
			action := udpRoutingAction(addr, true, allowlist, gateway)
			require.Equal(t, udpBlock, action,
				"blockAllOutbound must block addr=%s allowlist=%v",
				addr.String(), allowlist)
		}
	}
}

// TestUDPNoFilteringAlwaysAllows verifies that with both blockAllOutbound=false
// and no allowlist, all traffic is forwarded regardless of address.
func TestUDPNoFilteringAlwaysAllows(t *testing.T) {
	gateway := tcpip.AddrFrom4([4]byte{192, 168, 1, 1})

	addresses := []tcpip.Address{
		gateway,
		tcpip.AddrFrom4([4]byte{8, 8, 8, 8}),
		tcpip.AddrFrom4([4]byte{0, 0, 0, 0}),
		tcpip.AddrFrom4([4]byte{127, 0, 0, 1}),
		tcpip.AddrFrom4([4]byte{255, 255, 255, 255}),
	}

	for _, addr := range addresses {
		action := udpRoutingAction(addr, false, false, gateway)
		require.Equal(t, udpDirect, action,
			"no filtering must allow addr=%s", addr.String())
	}
}

// TestUDPAllowlistOnlyGatewayPasses verifies that when the allowlist is active
// (without blockAllOutbound), only the gateway address is forwarded.
func TestUDPAllowlistOnlyGatewayPasses(t *testing.T) {
	gateway := tcpip.AddrFrom4([4]byte{192, 168, 1, 1})

	blocked := []tcpip.Address{
		tcpip.AddrFrom4([4]byte{8, 8, 8, 8}),
		tcpip.AddrFrom4([4]byte{1, 1, 1, 1}),
		tcpip.AddrFrom4([4]byte{0, 0, 0, 0}),
		tcpip.AddrFrom4([4]byte{127, 0, 0, 1}),
		tcpip.AddrFrom4([4]byte{255, 255, 255, 255}),
		tcpip.AddrFrom4([4]byte{10, 0, 0, 1}),
		tcpip.AddrFrom4([4]byte{192, 168, 0, 1}),   // close to gateway but different
		tcpip.AddrFrom4([4]byte{192, 168, 1, 2}),   // same subnet, different host
		tcpip.AddrFrom4([4]byte{192, 168, 1, 0}),   // same subnet, network address
		tcpip.AddrFrom4([4]byte{192, 168, 1, 255}), // same subnet, broadcast
	}

	for _, addr := range blocked {
		action := udpRoutingAction(addr, false, true, gateway)
		require.Equal(t, udpBlock, action,
			"allowlist must block non-gateway addr=%s", addr.String())
	}

	action := udpRoutingAction(gateway, false, true, gateway)
	require.Equal(t, udpDirect, action, "allowlist must allow gateway")
}

// TestUDPRoutingActionZeroGateway verifies behavior when no gateway IP is
// configured (zero-value address). No address should match the gateway
// exemption except the zero address itself.
func TestUDPRoutingActionZeroGateway(t *testing.T) {
	var zeroGateway tcpip.Address
	other := tcpip.AddrFrom4([4]byte{8, 8, 8, 8})

	// Non-zero address is blocked when allowlist active
	action := udpRoutingAction(other, false, true, zeroGateway)
	require.Equal(t, udpBlock, action)

	// Zero address matches zero gateway — gets exempted
	action = udpRoutingAction(zeroGateway, false, true, zeroGateway)
	require.Equal(t, udpDirect, action)

	// blockAllOutbound still blocks everything
	action = udpRoutingAction(other, true, false, zeroGateway)
	require.Equal(t, udpBlock, action)

	action = udpRoutingAction(zeroGateway, true, true, zeroGateway)
	require.Equal(t, udpBlock, action)
}
