package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

type client struct {
	Conn   net.Conn
	Config *ssh.ClientConfig
}

func newClient(conn net.Conn, user string, key string) (*client, error) {
	config, err := newConfig(user, key)
	if err != nil {
		return nil, fmt.Errorf("Error getting config for native Go SSH: %s", err)
	}

	return &client{
		Conn:   conn,
		Config: config,
	}, nil
}

func newConfig(user string, keyFile string) (*ssh.ClientConfig, error) {
	key, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	privateKey, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(privateKey)},
		// #nosec G106
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Minute,
	}, nil
}

func (client *client) output(command string) (string, error) {
	c, chans, reqs, err := ssh.NewClientConn(client.Conn, "", client.Config)
	if err != nil {
		return "", err
	}
	conn := ssh.NewClient(c, chans, reqs)
	session, err := conn.NewSession()
	if err != nil {
		_ = conn.Close()
		return "", err
	}
	defer conn.Close()
	defer session.Close()

	output, err := session.CombinedOutput(command)
	if err != nil {
		return "", err
	}
	return string(output), nil
}
