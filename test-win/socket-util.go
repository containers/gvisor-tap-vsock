package e2ewin

import (
	"bufio"
	"fmt"
	"net"
	"strconv"

	"github.com/sirupsen/logrus"
)

//copypaste from https://github.com/containers/podman/blob/main/pkg/machine/sockets/sockets.go
// ListenAndWaitOnSocket waits for a new connection to the listener and sends
// any error back through the channel. ListenAndWaitOnSocket is intended to be
// used as a goroutine
func ListenAndWaitOnSocket(errChan chan<- error, listener net.Listener) {
	conn, err := listener.Accept()
	if err != nil {
		logrus.Debug("failed to connect to ready socket")
		errChan <- err
		return
	}
	_, err = bufio.NewReader(conn).ReadString('\n')

	if closeErr := conn.Close(); closeErr != nil {
		errChan <- closeErr
		return
	}

	errChan <- err
}
//copypaste from https://github.com/containers/podman/blob/main/utils/port.go
// Find a random, open port on the host.
func GetRandomPort() (int, error) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0, fmt.Errorf("unable to get free TCP port: %w", err)
	}
	defer l.Close()
	_, randomPort, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		return 0, fmt.Errorf("unable to determine free port: %w", err)
	}
	rp, err := strconv.Atoi(randomPort)
	if err != nil {
		return 0, fmt.Errorf("unable to convert random port to int: %w", err)
	}
	return rp, nil
}
