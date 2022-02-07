//go:build linux
// +build linux

package vsock

import (
	"net"
	"time"

	"github.com/mdlayher/socket"
	"golang.org/x/sys/unix"
)

var _ net.Listener = &listener{}

// A listener is the net.Listener implementation for connection-oriented
// VM sockets.
type listener struct {
	c    *socket.Conn
	addr *Addr
}

// Addr and Close implement the net.Listener interface for listener.
func (l *listener) Addr() net.Addr                { return l.addr }
func (l *listener) Close() error                  { return l.c.Close() }
func (l *listener) SetDeadline(t time.Time) error { return l.c.SetDeadline(t) }

// Accept accepts a single connection from the listener, and sets up
// a net.Conn backed by conn.
func (l *listener) Accept() (net.Conn, error) {
	c, rsa, err := l.c.Accept(0)
	if err != nil {
		return nil, err
	}

	savm := rsa.(*unix.SockaddrVM)
	remote := &Addr{
		ContextID: savm.CID,
		Port:      savm.Port,
	}

	return &Conn{
		c:      c,
		local:  l.addr,
		remote: remote,
	}, nil
}

// listen is the entry point for Listen on Linux.
func listen(cid, port uint32, _ *Config) (*Listener, error) {
	// TODO(mdlayher): Config default nil check and initialize. Pass options to
	// socket.Config where necessary.

	c, err := socket.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0, "vsock", nil)
	if err != nil {
		return nil, err
	}

	// Be sure to close the Conn if any of the system calls fail before we
	// return the Conn to the caller.

	if port == 0 {
		port = unix.VMADDR_PORT_ANY
	}

	if err := c.Bind(&unix.SockaddrVM{CID: cid, Port: port}); err != nil {
		_ = c.Close()
		return nil, err
	}

	if err := c.Listen(unix.SOMAXCONN); err != nil {
		_ = c.Close()
		return nil, err
	}

	lsa, err := c.Getsockname()
	if err != nil {
		_ = c.Close()
		return nil, err
	}

	lsavm := lsa.(*unix.SockaddrVM)
	addr := &Addr{
		ContextID: lsavm.CID,
		Port:      lsavm.Port,
	}

	return &Listener{
		l: &listener{
			c:    c,
			addr: addr,
		},
	}, nil
}
