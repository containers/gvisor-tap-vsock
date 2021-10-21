package main

import (
	"context"
	"io"
	"net"
	"net/url"
	"os"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/fs"
	"github.com/containers/gvisor-tap-vsock/pkg/sshclient"
	vnet "github.com/containers/gvisor-tap-vsock/pkg/virtualnetwork"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

type CloseWriteStream interface {
	io.Reader
	io.WriteCloser
	CloseWrite() error
}

type SSHForward struct {
	listener net.Listener
	bastion  *sshclient.Bastion
	sock     *url.URL
}

func CreateSSHForward(ctx context.Context, socket string, dest url.URL, identity string, vn *vnet.VirtualNetwork) (*SSHForward, error) {
	if err := os.Remove(socket); err != nil && !os.IsNotExist(err) {
		return &SSHForward{}, err
	}

	src := url.URL{
		Scheme: "unix",
		Path:   socket,
	}

	return setupProxy(ctx, &src, &dest, identity, vn)
}

func (forward *SSHForward) AcceptAndTunnel(ctx context.Context) error {
	return acceptConnection(ctx, forward.listener, forward.bastion, forward.sock)
}

func (forward *SSHForward) Close() {
	if forward.listener != nil {
		forward.listener.Close()
	}
	if forward.bastion != nil {
		forward.bastion.Close()
	}
}

func connectForward(ctx context.Context, bastion *sshclient.Bastion) (CloseWriteStream, error) {
	for retries := 1; ; retries++ {
		forward, err := bastion.Client.Dial("unix", bastion.Path)
		if err == nil {
			return forward.(ssh.Channel), nil
		}
		if retries > 2 {
			return nil, errors.Wrapf(err, "Couldn't restablish ssh tunnel on path: %s", bastion.Path)
		}
		// Check if ssh connection is still alive
		_, _, err = bastion.Client.Conn.SendRequest("alive@gvproxy", true, nil)
		if err != nil {
			for bastionRetries := 1; ; bastionRetries++ {
				err = bastion.Reconnect()
				if err == nil {
					break
				}
				if bastionRetries > 2 || !sleep(ctx, 200*time.Millisecond) {
					return nil, errors.Wrapf(err, "Couldn't reestablish ssh connection: %s", bastion.Host)
				}
			}
		}

		if !sleep(ctx, 200*time.Millisecond) {
			retries = 3
		}
	}
}

func listenUnix(socketURI *url.URL) (net.Listener, error) {
	oldmask := fs.Umask(0177)
	defer fs.Umask(oldmask)
	listener, err := net.Listen("unix", socketURI.Path)
	if err != nil {
		return listener, errors.Wrapf(err, "Error listening on socket: %s", socketURI.Path)
	}

	return listener, nil
}

func setupProxy(ctx context.Context, socketURI *url.URL, dest *url.URL, identity string, vn *vnet.VirtualNetwork) (*SSHForward, error) {
	listener, err := listenUnix(socketURI)
	if err != nil {
		return &SSHForward{}, err
	}

	connectFunc := func(bastion *sshclient.Bastion) (net.Conn, error) {
		timeout := 5 * time.Second
		if bastion != nil {
			timeout = bastion.Config.Timeout
		}
		ctx, cancel := context.WithTimeout(ctx, timeout)
		conn, err := vn.DialContextTCP(ctx, dest.Host)
		if cancel != nil {
			cancel()
		}

		return conn, err
	}

	conn, err := initialConnection(ctx, connectFunc)
	if err != nil {
		return &SSHForward{}, err
	}

	bastion, err := sshclient.CreateBastion(dest, "", identity, conn, connectFunc)
	if err != nil {
		return &SSHForward{}, err
	}

	logrus.Infof("Socket forward established: %s to %s\n", socketURI.Path, dest.Path)

	return &SSHForward{listener, &bastion, socketURI}, nil
}

func initialConnection(ctx context.Context, connectFunc sshclient.ConnectCallback) (net.Conn, error) {
	var (
		conn net.Conn
		err  error
	)

	backoff := 100 * time.Millisecond

loop:
	for i := 0; i < 60; i++ {
		select {
		case <-ctx.Done():
			break loop
		default:
			// proceed
		}

		conn, err = connectFunc(nil)
		if err == nil {
			break
		}
		logrus.Debugf("Waiting for sshd: %s", backoff)
		sleep(ctx, backoff)
		backoff = backOff(backoff)
	}
	return conn, err
}

func acceptConnection(ctx context.Context, listener net.Listener, bastion *sshclient.Bastion, socketURI *url.URL) error {
	con, err := listener.Accept()
	if err != nil {
		return errors.Wrapf(err, "Error accepting on socket: %s", socketURI.Path)
	}

	src, ok := con.(CloseWriteStream)
	if !ok {
		con.Close()
		return errors.Wrapf(err, "Underlying socket does not support half-close %s", socketURI.Path)
	}

	var dest CloseWriteStream

	dest, err = connectForward(ctx, bastion)
	if err != nil {
		con.Close()
		logrus.Error(err)
		return nil // eat
	}

	go forward(src, dest)
	go forward(dest, src)

	return nil
}

func forward(src io.ReadCloser, dest CloseWriteStream) {
	defer src.Close()
	_, _ = io.Copy(dest, src)

	// Trigger an EOF on the other end
	_ = dest.CloseWrite()
}

func backOff(delay time.Duration) time.Duration {
	if delay == 0 {
		delay = 5 * time.Millisecond
	} else {
		delay *= 2
	}
	if delay > time.Second {
		delay = time.Second
	}
	return delay
}

func sleep(ctx context.Context, wait time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(wait):
		return true
	}
}
