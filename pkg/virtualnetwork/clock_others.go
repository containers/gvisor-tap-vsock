//go:build !windows

package virtualnetwork

import "gvisor.dev/gvisor/pkg/tcpip"

// newClock returns nil, so the gVisor stack uses its default clock.
func newClock() tcpip.Clock {
	return nil
}
