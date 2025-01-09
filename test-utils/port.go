package e2eutils

import (
	"net"
	"strconv"
)

func IsPortAvailable(port int) bool {
	return IsHostPortAvailable("127.0.0.1", port)
}

func IsHostPortAvailable(host string, port int) bool {
	listener, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	listener.Close()
	return true
}
