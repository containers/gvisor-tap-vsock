package forwarder

// Modified version of https://github.com/moby/moby/blob/master/cmd/docker-proxy/udp_proxy.go and
// https://github.com/moby/vpnkit/blob/master/go/pkg/libproxy/udp_proxy.go

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	// UDPConnTrackTimeout is the timeout used for UDP connection tracking
	UDPConnTrackTimeout = 90 * time.Second
	// UDPBufSize is the buffer size for the UDP proxy
	UDPBufSize = 65507
)

// A net.Addr where the IP is split into two fields so you can use it as a key
// in a map:
type connTrackKey struct {
	IPHigh uint64
	IPLow  uint64
	Port   int
}

func newConnTrackKey(addr *net.UDPAddr) *connTrackKey {
	if len(addr.IP) == net.IPv4len {
		return &connTrackKey{
			IPHigh: 0,
			IPLow:  uint64(binary.BigEndian.Uint32(addr.IP)),
			Port:   addr.Port,
		}
	}
	return &connTrackKey{
		IPHigh: binary.BigEndian.Uint64(addr.IP[:8]),
		IPLow:  binary.BigEndian.Uint64(addr.IP[8:]),
		Port:   addr.Port,
	}
}

type trackedUDPConn struct {
	net.Conn
}

type connTrackMap map[connTrackKey]*trackedUDPConn

// UDPProxy is proxy for which handles UDP datagrams. It implements the Proxy
// interface to handle UDP traffic forwarding between the frontend and backend
// addresses.
type UDPProxy struct {
	listener       udpConn
	dialer         func(from net.Addr) (net.Conn, error)
	connTrackTable connTrackMap
	connTrackLock  sync.Mutex
}

// NewUDPProxy creates a new UDPProxy.
func NewUDPProxy(listener udpConn, dialer func(from net.Addr) (net.Conn, error)) (*UDPProxy, error) {
	return &UDPProxy{
		listener:       listener,
		connTrackTable: make(connTrackMap),
		dialer:         dialer,
	}, nil
}

func (proxy *UDPProxy) connFor(clientAddr net.Addr, clientKey connTrackKey) (*trackedUDPConn, error) {
	proxy.connTrackLock.Lock()
	defer proxy.connTrackLock.Unlock()
	if conn, ok := proxy.connTrackTable[clientKey]; ok {
		return conn, nil
	}

	conn, err := proxy.dialer(clientAddr)
	if err != nil {
		return nil, err
	}
	tracked := &trackedUDPConn{Conn: conn}
	proxy.connTrackTable[clientKey] = tracked
	go proxy.replyLoop(tracked, clientAddr, &clientKey)
	return tracked, nil
}

// removeConn drops a tracked socket only if it is still the current socket for
// the client. A reply loop for a retired socket may finish after a replacement
// has already been installed.
func (proxy *UDPProxy) removeConn(clientKey connTrackKey, conn *trackedUDPConn) {
	proxy.connTrackLock.Lock()
	if proxy.connTrackTable[clientKey] == conn {
		delete(proxy.connTrackTable, clientKey)
	}
	proxy.connTrackLock.Unlock()
	_ = conn.Close()
}

func (proxy *UDPProxy) replyLoop(proxyConn *trackedUDPConn, clientAddr net.Addr, clientKey *connTrackKey) {
	defer proxy.removeConn(*clientKey, proxyConn)

	readBuf := make([]byte, UDPBufSize)
	for {
		_ = proxyConn.SetReadDeadline(time.Now().Add(UDPConnTrackTimeout))
	again:
		read, err := proxyConn.Read(readBuf)
		if read == 0 && err == nil {
			// treat this condition same as EOF
			return
		}
		if err != nil {
			if err, ok := err.(*net.OpError); ok && err.Err == syscall.ECONNREFUSED {
				// This will happen if the last write failed
				// (e.g: nothing is actually listening on the
				// proxied port on the container), ignore it
				// and continue until UDPConnTrackTimeout
				// expires:
				goto again
			}
			return
		}
		for i := 0; i != read; {
			written, err := proxy.listener.WriteTo(readBuf[i:read], clientAddr)
			if err != nil {
				return
			}
			i += written
		}
	}
}

// Run starts forwarding the traffic using UDP.
func (proxy *UDPProxy) Run() {
	readBuf := make([]byte, UDPBufSize)
	for {
		read, from, err := proxy.listener.ReadFrom(readBuf)
		if err != nil {
			// NOTE: Apparently ReadFrom doesn't return
			// ECONNREFUSED like Read do (see comment in
			// UDPProxy.replyLoop)
			if !errors.Is(err, net.ErrClosed) {
				log.Debugf("Stopping udp proxy (%s)", err)
			}
			break
		}

		fromKey := newConnTrackKey(from.(*net.UDPAddr))
		proxyConn, err := proxy.connFor(from, *fromKey)
		if err != nil {
			log.Errorf("Can't proxy a datagram to udp: %s\n", err)
			continue
		}
		for i := 0; i != read; {
			_ = proxyConn.SetReadDeadline(time.Now().Add(UDPConnTrackTimeout))
			written, err := proxyConn.Write(readBuf[i:read])
			if errors.Is(err, syscall.EADDRNOTAVAIL) {
				// A connected UDP socket can remain bound to a source address
				// removed by a host network change. Retire it and retry this
				// datagram through a socket bound to the current route.
				proxy.removeConn(*fromKey, proxyConn)
				proxyConn, err = proxy.connFor(from, *fromKey)
				if err == nil {
					written, err = proxyConn.Write(readBuf[i:read])
				}
			}
			if err != nil {
				if errors.Is(err, syscall.EADDRNOTAVAIL) {
					proxy.removeConn(*fromKey, proxyConn)
				}
				log.Errorf("Can't proxy a datagram to udp: %s\n", err)
				break
			}
			i += written
		}
	}
}

// Close stops forwarding the traffic.
func (proxy *UDPProxy) Close() error {
	proxy.listener.Close()
	proxy.connTrackLock.Lock()
	defer proxy.connTrackLock.Unlock()
	for _, conn := range proxy.connTrackTable {
		_ = conn.Close()
	}
	return nil
}

type udpConn interface {
	ReadFrom(b []byte) (int, net.Addr, error)
	WriteTo(b []byte, addr net.Addr) (int, error)
	SetReadDeadline(t time.Time) error
	io.Closer
}

type autoStoppingListener struct {
	underlying udpConn
}

func (l *autoStoppingListener) ReadFrom(b []byte) (int, net.Addr, error) {
	_ = l.underlying.SetReadDeadline(time.Now().Add(UDPConnTrackTimeout))
	return l.underlying.ReadFrom(b)
}

func (l *autoStoppingListener) WriteTo(b []byte, addr net.Addr) (int, error) {
	_ = l.underlying.SetReadDeadline(time.Now().Add(UDPConnTrackTimeout))
	return l.underlying.WriteTo(b, addr)
}

func (l *autoStoppingListener) SetReadDeadline(t time.Time) error {
	return l.underlying.SetReadDeadline(t)
}

func (l *autoStoppingListener) Close() error {
	return l.underlying.Close()
}
