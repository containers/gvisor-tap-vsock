package sshclient

import (
	"errors"

	"golang.org/x/sys/windows"
)

// isConnRefused needs its own Windows implementation: there,
// syscall.ECONNREFUSED is a Go-defined value which never matches the
// WSAECONNREFUSED error returned by Winsock.
func isConnRefused(err error) bool {
	return errors.Is(err, windows.WSAECONNREFUSED)
}
