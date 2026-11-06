package forwarder

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/windows"
)

// SO_EXCLUSIVEADDRUSE is defined as ~SO_REUSEADDR in winsock2.h
const soExclusiveAddrUse = ^windows.SO_REUSEADDR

// exclusiveListenConfig sets SO_EXCLUSIVEADDRUSE on the host side of port
// forwards. Without it, Windows lets another process bind the same port on a
// more specific or different-family address (e.g. 0.0.0.0:443 next to our
// [::]:443), and connections are silently routed to that process instead.
// The option must be set between socket() and bind(), which is when Control runs.
var exclusiveListenConfig = net.ListenConfig{
	Control: func(_, _ string, c syscall.RawConn) error {
		var sockErr error
		if err := c.Control(func(fd uintptr) {
			sockErr = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, soExclusiveAddrUse, 1)
		}); err != nil {
			return err
		}
		return sockErr
	},
}

func listen(network, address string) (net.Listener, error) {
	return exclusiveListenConfig.Listen(context.Background(), network, address)
}
