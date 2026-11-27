package forwarder

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type udpProxyRead struct {
	data []byte
	addr net.Addr
	err  error
}

type testUDPListener struct {
	reads chan udpProxyRead
}

func (l *testUDPListener) ReadFrom(b []byte) (int, net.Addr, error) {
	packet := <-l.reads
	if packet.err != nil {
		return 0, nil, packet.err
	}
	return copy(b, packet.data), packet.addr, nil
}

func (*testUDPListener) WriteTo(b []byte, _ net.Addr) (int, error) { return len(b), nil }
func (*testUDPListener) SetReadDeadline(time.Time) error           { return nil }
func (*testUDPListener) Close() error                              { return nil }

type testProxyConn struct {
	writeErr       error
	writes         chan []byte
	holdRead       bool
	readStarted    chan struct{}
	resumeRead     chan struct{}
	closed         chan struct{}
	closedTwice    chan struct{}
	readStartedOne sync.Once
	closedOnce     sync.Once
	closedTwiceOne sync.Once
	closeCalls     atomic.Int32
}

func (c *testProxyConn) Read([]byte) (int, error) {
	c.readStartedOne.Do(func() { close(c.readStarted) })
	if c.holdRead {
		<-c.resumeRead
		return 0, net.ErrClosed
	}
	<-c.closed
	return 0, net.ErrClosed
}

func (c *testProxyConn) Write(b []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	c.writes <- append([]byte(nil), b...)
	return len(b), nil
}

func (c *testProxyConn) Close() error {
	if c.closeCalls.Add(1) >= 2 {
		c.closedTwiceOne.Do(func() { close(c.closedTwice) })
	}
	c.closedOnce.Do(func() { close(c.closed) })
	return nil
}

func (*testProxyConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*testProxyConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (*testProxyConn) SetDeadline(time.Time) error      { return nil }
func (*testProxyConn) SetReadDeadline(time.Time) error  { return nil }
func (*testProxyConn) SetWriteDeadline(time.Time) error { return nil }

func TestUDPProxyRedialsWhenSourceAddressDisappears(t *testing.T) {
	first := &testProxyConn{
		writeErr:    &net.OpError{Op: "write", Net: "udp", Err: syscall.EADDRNOTAVAIL},
		writes:      make(chan []byte, 2),
		holdRead:    true,
		readStarted: make(chan struct{}),
		resumeRead:  make(chan struct{}),
		closed:      make(chan struct{}),
		closedTwice: make(chan struct{}),
	}
	second := &testProxyConn{
		writes:      make(chan []byte, 2),
		readStarted: make(chan struct{}),
		resumeRead:  make(chan struct{}),
		closed:      make(chan struct{}),
		closedTwice: make(chan struct{}),
	}
	listener := &testUDPListener{reads: make(chan udpProxyRead, 3)}
	var dialCalls atomic.Int32
	proxy, err := NewUDPProxy(listener, func(net.Addr) (net.Conn, error) {
		if dialCalls.Add(1) == 1 {
			return first, nil
		}
		return second, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	runDone := make(chan struct{})
	go func() {
		proxy.Run()
		close(runDone)
	}()
	clientAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 12345}
	listener.reads <- udpProxyRead{data: []byte("first"), addr: clientAddr}
	select {
	case got := <-second.writes:
		if string(got) != "first" {
			t.Fatalf("replacement connection wrote %q, want first datagram", got)
		}
	case <-time.After(time.Second):
		t.Fatal("stale socket was not replaced and retried")
	}
	select {
	case <-first.readStarted:
	case <-time.After(time.Second):
		t.Fatal("old reply loop did not start")
	}

	// Let the old reply loop finish only after the replacement is in the map.
	// Its cleanup must not remove the new socket for the same client tuple.
	close(first.resumeRead)
	select {
	case <-first.closedTwice:
	case <-time.After(time.Second):
		t.Fatal("old reply loop did not finish")
	}

	listener.reads <- udpProxyRead{data: []byte("second"), addr: clientAddr}
	select {
	case got := <-second.writes:
		if string(got) != "second" {
			t.Fatalf("replacement connection wrote %q, want second datagram", got)
		}
	case <-time.After(time.Second):
		t.Fatal("old reply-loop cleanup removed the replacement connection")
	}
	if got := dialCalls.Load(); got != 2 {
		t.Fatalf("dialer called %d times, want 2", got)
	}

	listener.reads <- udpProxyRead{err: io.EOF}
	select {
	case <-runDone:
	case <-time.After(time.Second):
		t.Fatal("proxy Run did not stop after listener EOF")
	}
	if err := proxy.Close(); err != nil {
		t.Fatal(err)
	}
}
