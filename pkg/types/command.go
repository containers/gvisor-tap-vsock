package types

import (
	"fmt"
	"os/exec"
)

type Command struct {
	// Print packets on stderr
	Debug bool

	// Length of packet
	// Larger packets means less packets to exchange for the same amount of data (and less protocol overhead)
	MTU int

	// Values passed in by forward-xxx flags in commandline (forward-xxx:info)
	forwardInfo map[string][]string

	// List of endpoints the user wants to listen to
	endpoints []string

	// Map of different sockets provided by user (socket-type flag:socket)
	sockets map[string]string

	// File where gvproxy's pid is stored
	PidFile string

	// SSHPort to access the guest VM
	SSHPort int
}

func NewCommand() Command {
	return Command{
		MTU:         1500,
		SSHPort:     2222,
		endpoints:   []string{},
		forwardInfo: map[string][]string{},
		sockets:     map[string]string{},
	}
}

func (c *Command) checkSocketsInitialized() {
	if len(c.sockets) < 1 {
		c.sockets = map[string]string{}
	}
}

func (c *Command) checkForwardInfoInitialized() {
	if len(c.forwardInfo) < 1 {
		c.forwardInfo = map[string][]string{}
	}
}

func (c *Command) AddEndpoint(endpoint string) {
	if len(c.endpoints) < 1 {
		c.endpoints = []string{}
	}

	c.endpoints = append(c.endpoints, endpoint)
}

func (c *Command) AddVpnkitSocket(socket string) {
	c.checkSocketsInitialized()
	c.sockets["listen-vpnkit"] = socket
}

func (c *Command) AddQemuSocket(socket string) {
	c.checkSocketsInitialized()
	c.sockets["listen-qemu"] = socket
}

func (c *Command) AddBessSocket(socket string) {
	c.checkSocketsInitialized()
	c.sockets["listen-bess"] = socket
}

func (c *Command) AddStdioSocket(socket string) {
	c.checkSocketsInitialized()
	c.sockets["listen-stdio"] = socket
}

func (c *Command) AddVfkitSocket(socket string) {
	c.checkSocketsInitialized()
	c.sockets["listen-vfkit"] = socket
}

func (c *Command) addForwardInfo(flag, value string) {
	c.forwardInfo[flag] = append(c.forwardInfo[flag], value)
}

func (c *Command) AddForwardSock(socket string) {
	c.checkForwardInfoInitialized()
	c.addForwardInfo("forward-sock", socket)
}

func (c *Command) AddForwardDest(dest string) {
	c.checkForwardInfoInitialized()
	c.addForwardInfo("forward-dest", dest)
}

func (c *Command) AddForwardUser(user string) {
	c.checkForwardInfoInitialized()
	c.addForwardInfo("forward-user", user)
}

func (c *Command) AddForwardIdentity(identity string) {
	c.checkForwardInfoInitialized()
	c.addForwardInfo("forward-identity", identity)
}

// socketsToCmdline converts Command.sockets to a commandline format
func (c *Command) socketsToCmdline() []string {
	args := []string{}

	for socketFlag, socket := range c.sockets {
		if socket != "" {
			args = append(args, fmt.Sprintf("-%s %s", socketFlag, socket))
		}
	}

	return args
}

// forwardInfoToCmdline converts Command.forwardInfo to a commandline format
func (c *Command) forwardInfoToCmdline() []string {
	args := []string{}

	for forwardInfoFlag, forwardInfo := range c.forwardInfo {
		for _, i := range forwardInfo {
			if i != "" {
				args = append(args, fmt.Sprintf("-%s %s", forwardInfoFlag, i))
			}
		}
	}

	return args
}

// endpointsToCmdline converts Command.endpoints to a commandline format
func (c *Command) endpointsToCmdline() []string {
	args := []string{}

	for _, endpoint := range c.endpoints {
		if endpoint != "" {
			args = append(args, "-listen "+endpoint)
		}
	}

	return args
}

// ToCmdline converts Command to a properly formatted command for gvproxy based
// on its fields
func (c *Command) ToCmdline() []string {
	args := []string{}

	// listen (endpoints)
	args = append(args, c.endpointsToCmdline()...)

	// debug
	if c.Debug {
		args = append(args, "-debug")
	}

	// mtu
	args = append(args, fmt.Sprintf("-mtu %d", c.MTU))

	// ssh-port
	args = append(args, fmt.Sprintf("-ssh-port %d", c.SSHPort))

	// sockets
	args = append(args, c.socketsToCmdline()...)

	// forward info
	args = append(args, c.forwardInfoToCmdline()...)

	// pid-file
	if c.PidFile != "" {
		args = append(args, "-pid-file "+c.PidFile)
	}

	return args
}

// Cmd converts Command to a commandline format and returns an exec.Cmd which
// can be executed by os/exec
func (c *Command) Cmd(gvproxyPath string) *exec.Cmd {
	return exec.Command(gvproxyPath, c.ToCmdline()...) // #nosec G204
}
