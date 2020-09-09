package tap

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"

	log "github.com/golang/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/guillaumerose/gvisor-tap-vsock/pkg/types"
	"github.com/pkg/errors"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type LinkEndpoint struct {
	Sent     uint64
	Received uint64

	Listener            net.Listener
	Debug               bool
	Mac                 tcpip.LinkAddress
	MaxTransmissionUnit int

	conn     net.Conn
	connLock sync.Mutex

	dispatcher stack.NetworkDispatcher

	writeLock sync.Mutex
}

func (e *LinkEndpoint) AddHeader(local, remote tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
}

func (e *LinkEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareEther
}

func (e *LinkEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
}

func (e *LinkEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityResolutionRequired | stack.CapabilityRXChecksumOffload
}

func (e *LinkEndpoint) IsAttached() bool {
	return e.dispatcher != nil
}

func (e *LinkEndpoint) LinkAddress() tcpip.LinkAddress {
	return e.Mac
}

func (e *LinkEndpoint) MaxHeaderLength() uint16 {
	return uint16(header.EthernetMinimumSize)
}

func (e *LinkEndpoint) MTU() uint32 {
	return uint32(e.MaxTransmissionUnit)
}

func (e *LinkEndpoint) Wait() {
}

func (e *LinkEndpoint) WritePackets(r *stack.Route, gso *stack.GSO, pkts stack.PacketBufferList, protocol tcpip.NetworkProtocolNumber) (int, *tcpip.Error) {
	return 1, tcpip.ErrNoRoute
}

func (e *LinkEndpoint) WritePacket(r *stack.Route, gso *stack.GSO, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) *tcpip.Error {
	// Preserve the src address if it's set in the route.
	srcAddr := e.Mac
	if r.LocalLinkAddress != "" {
		srcAddr = r.LocalLinkAddress
	}
	eth := header.Ethernet(pkt.LinkHeader().Push(header.EthernetMinimumSize))
	eth.Encode(&header.EthernetFields{
		Type:    protocol,
		SrcAddr: srcAddr,
		DstAddr: r.RemoteLinkAddress,
	})

	if e.Debug {
		vv := buffer.NewVectorisedView(pkt.Size(), pkt.Views())
		packet := gopacket.NewPacket(vv.ToView(), layers.LayerTypeEthernet, gopacket.Default)
		log.Info(packet.String())
	}

	if err := e.writeSockets(pkt); err != nil {
		log.Error(errors.Wrap(err, "cannot send packets"))
		return tcpip.ErrAborted
	}
	return nil
}

func (e *LinkEndpoint) writeSockets(pkt *stack.PacketBuffer) error {
	size := make([]byte, 2)
	binary.LittleEndian.PutUint16(size, uint16(pkt.Size()))

	e.writeLock.Lock()
	defer e.writeLock.Unlock()

	e.connLock.Lock()
	defer e.connLock.Unlock()

	if e.conn == nil {
		return nil
	}

	if _, err := e.conn.Write(size); err != nil {
		e.conn.Close()
		e.conn = nil
		return err
	}
	for _, view := range pkt.Views() {
		if _, err := e.conn.Write(view); err != nil {
			e.conn.Close()
			e.conn = nil
			return err
		}
	}

	atomic.AddUint64(&e.Sent, uint64(pkt.Size()))
	return nil
}

func (e *LinkEndpoint) WriteRawPacket(vv buffer.VectorisedView) *tcpip.Error {
	return tcpip.ErrNoRoute
}

func (e *LinkEndpoint) AcceptOne(gateway, vm string) error {
	log.Info("waiting for packets...")
	for {
		conn, err := e.Listener.Accept()
		if err != nil {
			return errors.Wrap(err, "cannot accept new client")
		}
		e.connLock.Lock()

		if err := e.handshake(conn, gateway, vm); err != nil {
			return errors.Wrap(err, "cannot handshake")
		}

		e.conn = conn
		e.connLock.Unlock()
		go func() {
			defer func() {
				e.connLock.Lock()
				e.conn = nil
				e.connLock.Unlock()
				conn.Close()
			}()
			if err := rx(conn, e); err != nil {
				log.Error(errors.Wrap(err, "cannot receive packets"))
				return
			}
		}()
	}
}

func (e *LinkEndpoint) handshake(conn net.Conn, gateway string, vm string) error {
	bin, err := json.Marshal(&types.Handshake{
		MTU:     e.MaxTransmissionUnit,
		Gateway: gateway,
		VM:      vm,
	})
	if err != nil {
		return err
	}
	size := make([]byte, 2)
	binary.LittleEndian.PutUint16(size, uint16(len(bin)))
	if _, err := conn.Write(size); err != nil {
		return err
	}
	if _, err := conn.Write(bin); err != nil {
		return err
	}
	return nil
}

func rx(conn net.Conn, e *LinkEndpoint) error {
	sizeBuf := make([]byte, 2)

	for {
		n, err := io.ReadFull(conn, sizeBuf)
		if err != nil {
			return errors.Wrap(err, "cannot read size from socket")
		}
		if n != 2 {
			return fmt.Errorf("unexpected size %d", n)
		}
		size := int(binary.LittleEndian.Uint16(sizeBuf[0:2]))

		buf := make([]byte, e.MaxTransmissionUnit+header.EthernetMinimumSize)
		n, err = io.ReadFull(conn, buf[:size])
		if err != nil {
			return errors.Wrap(err, "cannot read packet from socket")
		}
		if n == 0 || n != size {
			return fmt.Errorf("unexpected size %d != %d", n, size)
		}

		if e.Debug {
			packet := gopacket.NewPacket(buf[:size], layers.LayerTypeEthernet, gopacket.Default)
			log.Info(packet.String())
		}

		view := buffer.View(buf[:size])
		eth := header.Ethernet(view)
		vv := buffer.NewVectorisedView(len(view), []buffer.View{view})
		vv.TrimFront(header.EthernetMinimumSize)

		if e.dispatcher == nil {
			continue
		}
		atomic.AddUint64(&e.Received, uint64(size))
		e.dispatcher.DeliverNetworkPacket(
			eth.SourceAddress(),
			eth.DestinationAddress(),
			eth.Type(),
			&stack.PacketBuffer{
				Data: vv,
			},
		)
	}
}
