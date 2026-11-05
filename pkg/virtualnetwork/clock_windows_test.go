//go:build windows

package virtualnetwork

import (
	"testing"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/tap"
	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestStackUsesClock(t *testing.T) {
	endpoint, err := tap.NewLinkEndpoint(false, 1500, "5a:94:ef:e4:0c:dd", "192.168.127.1", nil)
	require.NoError(t, err)
	s, err := createStack(&types.Configuration{
		Subnet:    "192.168.127.0/24",
		GatewayIP: "192.168.127.1",
	}, endpoint)
	require.NoError(t, err)
	defer s.Close()
	require.IsType(t, &qpcClock{}, s.Clock())
}

func TestClockResolution(t *testing.T) {
	// TCP compares transmit times and takes RTT samples from NowMonotonic, so
	// it must move in steps much smaller than a round trip to the VM. Go's
	// monotonic clock mostly moves at the system timer tick on Windows: every
	// 0.5 ms at best. Up to a few hundred steps a second can still be
	// shorter, so the test needs many more fine steps.
	const (
		fineStep  = 50 * time.Microsecond
		wantSteps = 10000
		timeout   = time.Second
	)
	c := newClock()
	require.NotNil(t, c)

	prev := c.NowMonotonic()
	steps := 0
	for deadline := time.Now().Add(timeout); steps < wantSteps && time.Now().Before(deadline); {
		now := c.NowMonotonic()
		require.False(t, now.Before(prev), "the clock went backwards")
		if step := now.Sub(prev); step > 0 && step < fineStep {
			steps++
		}
		prev = now
	}
	require.GreaterOrEqual(t, steps, wantSteps, "steps of NowMonotonic under %v in %v", fineStep, timeout)
}

func TestClockKeepsTime(t *testing.T) {
	c := newClock()
	require.NotNil(t, c)

	start, wallStart := c.NowMonotonic(), time.Now()
	time.Sleep(500 * time.Millisecond)
	elapsed, wallElapsed := c.NowMonotonic().Sub(start), time.Since(wallStart)
	// time.Now can be a 15.6 ms timer tick behind, and the runner may pause
	// the test between the two reads.
	require.InDelta(t, wallElapsed.Seconds(), elapsed.Seconds(), 0.05)
}

func BenchmarkClockNowMonotonic(b *testing.B) {
	c := newClock()
	b.ReportAllocs()
	for b.Loop() {
		c.NowMonotonic()
	}
}
