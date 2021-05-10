package virtualnetwork

import (
	"net"
)

func (n *VirtualNetwork) AcceptQemu(conn net.Conn) error {
	n.networkSwitch.Accept(conn)
	return nil
}
