package e2eutils

import (
	"fmt"
	"net"
)

func IsPortAvailable(port int) bool {
	return IsHostPortAvailable("127.0.0.1", port)
}

func IsHostPortAvailable(host string, port int) bool {
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return false
	}
	listener.Close()
	return true
}
