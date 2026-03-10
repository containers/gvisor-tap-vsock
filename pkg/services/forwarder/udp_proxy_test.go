package forwarder

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// mockUDPConn implements udpConn interface for testing
type mockUDPConn struct {
	readFromCalls int32
	writeToErr    error
	closeCalled   bool
	mu            sync.Mutex
}

func (m *mockUDPConn) ReadFrom(b []byte) (int, net.Addr, error) {
	m.mu.Lock()
	closed := m.closeCalled
	m.mu.Unlock()

	if closed {
		return 0, nil, net.ErrClosed
	}

	atomic.AddInt32(&m.readFromCalls, 1)
	// Add a small delay to prevent tight loop in tests
	time.Sleep(1 * time.Millisecond)
	// Return a test packet
	copy(b, []byte("test"))
	return 4, &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 5000}, nil
}

func (m *mockUDPConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if m.writeToErr != nil {
		return 0, m.writeToErr
	}
	return len(b), nil
}

func (m *mockUDPConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockUDPConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closeCalled = true
	return nil
}

// mockConn implements net.Conn that returns ECONNREFUSED repeatedly
type mockECONNREFUSEDConn struct {
	readCalls   int32
	writeCalls  int32
	writeErr    error
	closed      bool
	mu          sync.Mutex
}

func (m *mockECONNREFUSEDConn) Read(b []byte) (int, error) {
	atomic.AddInt32(&m.readCalls, 1)
	// Simulate persistent ECONNREFUSED (e.g., from queued ICMP errors)
	return 0, &net.OpError{
		Op:  "read",
		Net: "udp",
		Err: syscall.ECONNREFUSED,
	}
}

func (m *mockECONNREFUSEDConn) Write(b []byte) (int, error) {
	atomic.AddInt32(&m.writeCalls, 1)
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	return len(b), nil
}

func (m *mockECONNREFUSEDConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *mockECONNREFUSEDConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
}

func (m *mockECONNREFUSEDConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 123}
}

func (m *mockECONNREFUSEDConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockECONNREFUSEDConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockECONNREFUSEDConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// TestUDPProxy_ECONNREFUSEDInfiniteLoop tests that the replyLoop doesn't
// spin infinitely when receiving persistent ECONNREFUSED errors.
// This reproduces the bug where gvproxy consumes 100% CPU after macOS sleep
// when NTP connections receive persistent ICMP errors.
func TestUDPProxy_ECONNREFUSEDInfiniteLoop(t *testing.T) {
	listener := &mockUDPConn{}

	// Create a connection that will always return ECONNREFUSED
	mockConn := &mockECONNREFUSEDConn{}

	dialer := func() (net.Conn, error) {
		return mockConn, nil
	}

	proxy, err := NewUDPProxy(listener, dialer)
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}

	// Create a context with timeout to prevent test from hanging forever
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Start the proxy in a goroutine
	proxyDone := make(chan struct{})
	go func() {
		proxy.Run()
		close(proxyDone)
	}()

	// Give it a moment to start and process
	time.Sleep(100 * time.Millisecond)

	// Trigger a connection by simulating incoming data
	// The proxy will create a connection via dialer and start replyLoop
	initialReadCalls := atomic.LoadInt32(&mockConn.readCalls)

	// Wait a bit and check if read calls are spinning out of control
	time.Sleep(500 * time.Millisecond)

	finalReadCalls := atomic.LoadInt32(&mockConn.readCalls)
	readCallsPerSecond := float64(finalReadCalls-initialReadCalls) / 0.5

	// Clean up
	proxy.Close()

	// Wait for proxy to finish or timeout
	select {
	case <-proxyDone:
		// Good, proxy finished
	case <-ctx.Done():
		t.Error("Proxy did not shut down cleanly within timeout")
	}

	// If we're making thousands of read calls per second, we have a busy loop
	// A properly functioning implementation should block on Read() and make
	// very few calls per second when timing out naturally.
	// With a 90s timeout and occasional retries, we should see < 100 calls/sec
	if readCallsPerSecond > 1000 {
		t.Errorf("replyLoop appears to be in an infinite busy loop: %.0f read calls per second (expected < 1000)", readCallsPerSecond)
		t.Logf("Total read calls: initial=%d, final=%d, rate=%.0f/sec",
			initialReadCalls, finalReadCalls, readCallsPerSecond)
	}
}

// TestUDPProxy_ECONNREFUSEDEventuallyExits tests that replyLoop eventually
// exits when receiving ECONNREFUSED errors, rather than spinning forever.
func TestUDPProxy_ECONNREFUSEDEventuallyExits(t *testing.T) {
	listener := &mockUDPConn{}
	mockConn := &mockECONNREFUSEDConn{}

	dialer := func() (net.Conn, error) {
		return mockConn, nil
	}

	proxy, err := NewUDPProxy(listener, dialer)
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}
	defer proxy.Close()

	// Manually trigger replyLoop with a connection
	fromAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 5000}
	fromKey := newConnTrackKey(fromAddr)

	proxy.connTrackLock.Lock()
	proxy.connTrackTable[*fromKey] = mockConn
	proxy.connTrackLock.Unlock()

	// Start replyLoop
	replyLoopDone := make(chan struct{})
	go func() {
		proxy.replyLoop(mockConn, fromAddr, fromKey)
		close(replyLoopDone)
	}()

	// replyLoop should exit within a reasonable time (not spin forever)
	// Even with retries, it should terminate within a few seconds
	select {
	case <-replyLoopDone:
		// Good - replyLoop exited
		t.Log("replyLoop exited as expected")
	case <-time.After(5 * time.Second):
		t.Error("replyLoop did not exit within 5 seconds - likely stuck in infinite loop")

		// Check how many read calls were made
		readCalls := atomic.LoadInt32(&mockConn.readCalls)
		if readCalls > 10000 {
			t.Errorf("replyLoop made %d read calls in 5 seconds (likely infinite loop)", readCalls)
		}
	}

	// Verify connection was cleaned up from tracking table
	proxy.connTrackLock.Lock()
	_, exists := proxy.connTrackTable[*fromKey]
	proxy.connTrackLock.Unlock()

	if exists {
		t.Error("Connection was not removed from tracking table after replyLoop exit")
	}
}

// smartECONNREFUSEDConn returns ECONNREFUSED a few times then succeeds
type smartECONNREFUSEDConn struct {
	readCalls    int32
	writeCalls   int32
	successAfter int32
	closed       bool
	mu           sync.Mutex
}

func (m *smartECONNREFUSEDConn) Read(b []byte) (int, error) {
	calls := atomic.AddInt32(&m.readCalls, 1)
	if calls <= m.successAfter {
		// Return ECONNREFUSED for the first few calls
		return 0, &net.OpError{
			Op:  "read",
			Net: "udp",
			Err: syscall.ECONNREFUSED,
		}
	}
	// After a few failures, return success with some data once
	if calls == m.successAfter+1 {
		copy(b, []byte("response"))
		return 8, nil
	}
	// Then block/timeout normally (simulate real UDP behavior)
	time.Sleep(100 * time.Millisecond)
	return 0, &net.OpError{
		Op:  "read",
		Net: "udp",
		Err: errors.New("i/o timeout"),
	}
}

func (m *smartECONNREFUSEDConn) Write(b []byte) (int, error) {
	atomic.AddInt32(&m.writeCalls, 1)
	return len(b), nil
}

func (m *smartECONNREFUSEDConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *smartECONNREFUSEDConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
}

func (m *smartECONNREFUSEDConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 123}
}

func (m *smartECONNREFUSEDConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *smartECONNREFUSEDConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *smartECONNREFUSEDConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// TestUDPProxy_TransientECONNREFUSED tests that transient ECONNREFUSED errors
// (the original intended behavior) still work correctly.
func TestUDPProxy_TransientECONNREFUSED(t *testing.T) {
	listener := &mockUDPConn{}

	mockConn := &smartECONNREFUSEDConn{
		successAfter: 3, // Succeed after 3 ECONNREFUSED errors
	}

	dialer := func() (net.Conn, error) {
		return mockConn, nil
	}

	proxy, err := NewUDPProxy(listener, dialer)
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}
	defer proxy.Close()

	fromAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 5000}
	fromKey := newConnTrackKey(fromAddr)

	proxy.connTrackLock.Lock()
	proxy.connTrackTable[*fromKey] = mockConn
	proxy.connTrackLock.Unlock()

	// Start replyLoop
	replyLoopDone := make(chan struct{})
	go func() {
		proxy.replyLoop(mockConn, fromAddr, fromKey)
		close(replyLoopDone)
	}()

	// Give it time to process
	time.Sleep(200 * time.Millisecond)

	// Check that it retried a few times (should be > successAfter)
	readCalls := atomic.LoadInt32(&mockConn.readCalls)
	if readCalls < mockConn.successAfter {
		t.Errorf("Expected at least %d read calls (for retries), got %d", mockConn.successAfter, readCalls)
	}

	// Verify it didn't make thousands of calls (no infinite loop)
	if readCalls > 100 {
		t.Errorf("Made too many read calls (%d), possible infinite loop", readCalls)
	}

	proxy.Close()

	select {
	case <-replyLoopDone:
		t.Log("replyLoop completed successfully")
	case <-time.After(2 * time.Second):
		t.Error("replyLoop did not complete within timeout")
	}
}

// TestUDPProxy_NetworkUnreachableError tests handling of "network unreachable"
// errors that appear in the bug report logs.
func TestUDPProxy_NetworkUnreachableError(t *testing.T) {
	listener := &mockUDPConn{}

	mockConn := &mockECONNREFUSEDConn{
		writeErr: &net.OpError{
			Op:  "write",
			Net: "udp",
			Err: errors.New("connect: network is unreachable"),
		},
	}

	dialCalled := int32(0)
	dialer := func() (net.Conn, error) {
		atomic.AddInt32(&dialCalled, 1)
		if atomic.LoadInt32(&dialCalled) == 1 {
			// First dial succeeds but writes will fail
			return mockConn, nil
		}
		// Subsequent dials fail
		return nil, errors.New("dial udp 192.36.143.130:123: connect: network is unreachable")
	}

	proxy, err := NewUDPProxy(listener, dialer)
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}

	// Start proxy
	go proxy.Run()

	// Give it time to process some packets
	time.Sleep(200 * time.Millisecond)

	proxy.Close()

	// Verify we didn't get into an infinite loop
	// The listener's ReadFrom should not have been called excessively
	readFromCalls := atomic.LoadInt32(&listener.readFromCalls)
	if readFromCalls > 1000 {
		t.Errorf("Made %d ReadFrom calls, possible infinite loop in Run()", readFromCalls)
	}
}
