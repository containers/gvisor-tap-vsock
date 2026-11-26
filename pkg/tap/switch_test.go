package tap

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type fakeGateway struct {
	delivered chan tcpip.NetworkProtocolNumber
}

func (g *fakeGateway) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, _ *stack.PacketBuffer) {
	g.delivered <- protocol
}

func (g *fakeGateway) LinkAddress() tcpip.LinkAddress {
	return tcpip.LinkAddress("\x5a\x94\xef\xe4\x0c\xdd")
}

func (g *fakeGateway) IP() string {
	return "192.168.127.1"
}

func writeQemuFrame(conn net.Conn, frame []byte) bool {
	size := make([]byte, 4)
	binary.BigEndian.PutUint32(size, uint32(len(frame))) //#nosec: G115
	_, err := conn.Write(append(size, frame...))
	return err == nil
}

// A frame shorter than an Ethernet header must be dropped without
// affecting the connection or the rest of the switch.
func TestSwitchDropsFramesShorterThanEthernetHeader(t *testing.T) {
	gateway := &fakeGateway{delivered: make(chan tcpip.NetworkProtocolNumber, 1)}
	sw := NewSwitch(false)
	sw.Connect(gateway)

	guest, host := net.Pipe()
	defer guest.Close()

	acceptDone := make(chan error, 1)
	go func() {
		acceptDone <- sw.Accept(context.Background(), host, types.QemuProtocol)
	}()

	// net.Pipe is synchronous: write from a goroutine so that a switch
	// that stops reading makes the test fail instead of hang
	src := tcpip.LinkAddress("\x02\x00\x00\x00\x00\x01")
	go func() {
		for _, size := range []int{0, 1, 5, 11, 12, 13} {
			if !writeQemuFrame(guest, make([]byte, size)) {
				return
			}
		}

		// a valid frame sent afterwards on the same connection is still handled
		frame := make([]byte, header.EthernetMinimumSize)
		header.Ethernet(frame).Encode(&header.EthernetFields{
			SrcAddr: src,
			DstAddr: gateway.LinkAddress(),
			Type:    header.IPv4ProtocolNumber,
		})
		writeQemuFrame(guest, frame)
	}()

	select {
	case protocol := <-gateway.delivered:
		assert.Equal(t, header.IPv4ProtocolNumber, protocol)
	case <-time.After(5 * time.Second):
		t.Fatal("valid frame sent after short frames was not delivered to the gateway")
	}

	camDone := make(chan map[string]int, 1)
	go func() {
		camDone <- sw.CAM()
	}()
	select {
	case cam := <-camDone:
		assert.Equal(t, map[string]int{src.String(): 0}, cam)
	case <-time.After(5 * time.Second):
		t.Fatal("CAM() blocked: the switch lock is still held")
	}

	require.NoError(t, guest.Close())
	select {
	case err := <-acceptDone:
		assert.Error(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Accept did not return after the connection was closed")
	}
}
