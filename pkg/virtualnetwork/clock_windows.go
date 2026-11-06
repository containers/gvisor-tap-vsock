//go:build windows

package virtualnetwork

import (
	"syscall"
	"time"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"gvisor.dev/gvisor/pkg/tcpip"
)

var (
	kernel32                      = windows.NewLazySystemDLL("kernel32.dll")
	procQueryPerformanceCounter   = kernel32.NewProc("QueryPerformanceCounter")
	procQueryPerformanceFrequency = kernel32.NewProc("QueryPerformanceFrequency")
)

// newClock returns the clock of the gVisor stack.
//
// On Windows, Go's monotonic clock reads the interrupt time, which only moves
// when the system timer fires: every 15.6 ms by default, 0.5 ms at best. TCP
// takes its RTT samples and the transmit times RACK compares from this clock.
// With a VM a few microseconds away, most RTT samples are 0 and segments sent
// in the same tick get the same transmit time, so RACK marks segments lost
// that were not and they are resent at once.
// QueryPerformanceCounter typically has a resolution of 100 ns.
//
// Go 1.28 gives the monotonic clock on Windows a resolution of 100 ns, so
// once go.mod requires Go 1.28, the clock_*.go files can be removed and the
// stack can use its default clock again.
func newClock() tcpip.Clock {
	if err := procQueryPerformanceCounter.Find(); err != nil {
		log.Warnf("TCP will use the default clock: %v", err)
		return nil
	}
	var freq int64
	if r, _, err := procQueryPerformanceFrequency.Call(uintptr(unsafe.Pointer(&freq))); r == 0 {
		log.Warnf("TCP will use the default clock: cannot read the performance counter frequency: %v", err)
		return nil
	}
	if freq <= 0 {
		log.Warnf("TCP will use the default clock: invalid performance counter frequency %d", freq)
		return nil
	}
	c := &qpcClock{
		Clock:   tcpip.NewStdClock(),
		counter: procQueryPerformanceCounter.Addr(),
		freq:    freq,
	}
	c.base = c.ticks()
	return c
}

// qpcClock is the default clock with NowMonotonic read from
// QueryPerformanceCounter.
type qpcClock struct {
	tcpip.Clock
	counter uintptr
	freq    int64
	base    int64
}

func (c *qpcClock) NowMonotonic() tcpip.MonotonicTime {
	ticks := c.ticks() - c.base
	elapsed := time.Duration(ticks/c.freq)*time.Second + time.Duration(ticks%c.freq*int64(time.Second)/c.freq)
	return tcpip.MonotonicTime{}.Add(elapsed)
}

func (c *qpcClock) ticks() int64 {
	var ticks int64
	// syscall.SyscallN, unlike LazyProc.Call, does not move ticks to the heap.
	// QueryPerformanceCounter cannot fail on Windows XP or later.
	_, _, _ = syscall.SyscallN(c.counter, uintptr(unsafe.Pointer(&ticks)))
	return ticks
}
