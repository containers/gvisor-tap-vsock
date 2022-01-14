// +build windows

package e2e

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

const fakeHostKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAkXGLzDNnY5+xdAgnt8FlBIZtoFOZEdTUkNxkdSM05PgAAAJg9WMAvPVjA
LwAAAAtzc2gtZWQyNTUxOQAAACAkXGLzDNnY5+xdAgnt8FlBIZtoFOZEdTUkNxkdSM05Pg
AAAEAFvLprhpMPdNsxSwo1Cs5VP5joCh9XLicRqKE0JJzdxCRcYvMM2djn7F0CCe3wWUEh
m2gU5kR1NSQ3GR1IzTk+AAAAEmphc29uQFRyaXBlbC5sb2NhbAECAw==
-----END OPENSSH PRIVATE KEY-----`

type streamLocalDirect struct {
	SocketPath string
	Reserved0  string
	Reserved1  uint32
}

var cancel context.CancelFunc

func startMockServer() {
	sshConfig := &ssh.ServerConfig{
		NoClientAuth: true,
	}

	key, err := ssh.ParsePrivateKey([]byte(fakeHostKey))
	if err != nil {
		logrus.Errorf("Could not parse key: %s", err)
	}
	sshConfig.AddHostKey(key)

	listener, err := net.Listen("tcp", ":2134")
	if err != nil {
		panic(err)
	}

	var ctx context.Context
	ctx, cancel = context.WithCancel(context.Background())

	go func() {
	loop:
		for {
			select {
			case <-ctx.Done():
				break loop
			default:
				// proceed
			} 
			conn, err := listener.Accept()
			if err != nil {
				panic(err)
			}

			// From a standard TCP connection to an encrypted SSH connection
			_, chans, reqs, err := ssh.NewServerConn(conn, sshConfig)
			if err != nil {
				panic(err)
			}

			go handleRequests(reqs)
			// Accept all channels
			go handleChannels(chans)
		}
		listener.Close()
	}()
}

func stopMockServer() {
	cancel()
}

func handleRequests(reqs <-chan *ssh.Request) {
	for _ = range reqs {
	}
}

func handleChannels(chans <-chan ssh.NewChannel) {
	directMsg := streamLocalDirect{}
	for newChannel := range chans {
		if t := newChannel.ChannelType(); t != "direct-streamlocal@openssh.com" {
			newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
			continue
		}

		if err := ssh.Unmarshal(newChannel.ExtraData(), &directMsg); err != nil {
			logrus.Errorf("could not direct-streamlocal data: %s", err)

			newChannel.Reject(ssh.Prohibited, "invalid format")
			return
		}

		channel, _, err := newChannel.Accept()
		if err != nil {
			logrus.Errorf("could not accept channel: %s", err)
			continue
		}

		req, err := http.ReadRequest(bufio.NewReader(channel))
		if err != nil {
			logrus.Errorf("could not process http request: %s", err)
		}

		resp := http.Response{}
		resp.Close = true
		switch req.RequestURI {
		case "/ping":
			resp.StatusCode = 200
			resp.ContentLength = 4
			resp.Body = io.NopCloser(strings.NewReader("pong"))
		default:
			resp.StatusCode = 404
			resp.ContentLength = 0
		}
		resp.Write(channel)
		channel.CloseWrite()
	}
}
