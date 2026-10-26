//go:build !windows

package sshclient

import (
	"errors"
	"syscall"
)

func isConnRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}
