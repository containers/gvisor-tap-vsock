package tap

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/code-ready/gvisor-tap-vsock/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type VirtualDevice interface {
	DeliverNetworkPacket(remote, local tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer)
	LinkAddress() tcpip.LinkAddress
}

type NetworkSwitch interface {
	MTU() uint32
	DeliverNetworkPacket(remote, local tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer)
}

type Switch struct {
	Sent     uint64
	Received uint64

	listeners           []net.Listener
	debug               bool
	maxTransmissionUnit int

	nextConnID int
	conns      map[int]net.Conn
	connLock   sync.Mutex

	cam     map[tcpip.LinkAddress]int
	camLock sync.RWMutex

	writeLock sync.Mutex

	gatewayIP string
	gateway   VirtualDevice
	ipPool    *IPPool
}

func NewSwitch(listeners []net.Listener, debug bool, mtu int, ipPool *IPPool) *Switch {
	return &Switch{
		listeners:           listeners,
		debug:               debug,
		maxTransmissionUnit: mtu,
		conns:               make(map[int]net.Conn),
		cam:                 make(map[tcpip.LinkAddress]int),
		ipPool:              ipPool,
	}
}

func (e *Switch) Connect(ip string, ep VirtualDevice) {
	e.ipPool.Reserve(net.ParseIP(ip), -1)
	e.gatewayIP = ip
	e.gateway = ep
}

func (e *Switch) MTU() uint32 {
	return uint32(e.maxTransmissionUnit)
}

func (e *Switch) DeliverNetworkPacket(remote, local tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	if err := e.tx(remote, local, pkt); err != nil {
		log.Error(err)
	}
}

func (e *Switch) Run() error {
	log.Info("waiting for clients...")
	errCh := make(chan error)
	for i := range e.listeners {
		ln := e.listeners[i]
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					errCh <- errors.Wrap(err, "cannot accept new client")
				}

				go func() {
					log.Infof("new connection from %s", conn.LocalAddr().String())
					id, failed := e.connect(conn)
					if failed {
						log.Error("connection failed")
						return
					}

					defer func() {
						e.connLock.Lock()
						defer e.connLock.Unlock()
						e.disconnect(id, conn)
					}()
					if err := e.rx(id, conn); err != nil {
						log.Error(errors.Wrapf(err, "cannot receive packets from %s, disconnecting", conn.LocalAddr().String()))
						return
					}
				}()
			}
		}()
	}
	return <-errCh
}

func (e *Switch) connect(conn net.Conn) (int, bool) {
	e.connLock.Lock()
	defer e.connLock.Unlock()

	id := e.nextConnID
	e.nextConnID++

	ip, err := e.ipPool.Assign(id)
	if err != nil {
		log.Error(err)
		return 0, true
	}
	if err := e.handshake(conn, fmt.Sprintf("%s/%d", ip, e.ipPool.Mask())); err != nil {
		log.Error(errors.Wrapf(err, "cannot handshake with %s", conn.LocalAddr().String()))
		return 0, true
	}

	e.conns[id] = conn
	return id, false
}

func (e *Switch) handshake(conn net.Conn, vm string) error {
	log.Infof("assigning %s to %s", vm, conn.LocalAddr().String())
	bin, err := json.Marshal(&types.Handshake{
		MTU:     e.maxTransmissionUnit,
		Gateway: e.gatewayIP,
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

func (e *Switch) tx(dst, src tcpip.LinkAddress, pkt *stack.PacketBuffer) error {
	size := make([]byte, 2)
	binary.LittleEndian.PutUint16(size, uint16(pkt.Size()))

	e.writeLock.Lock()
	defer e.writeLock.Unlock()

	e.connLock.Lock()
	defer e.connLock.Unlock()

	if dst == header.EthernetBroadcastAddress {
		e.camLock.RLock()
		srcID, ok := e.cam[src]
		if !ok {
			e.camLock.RUnlock()
			return nil
		}
		e.camLock.RUnlock()
		for id, conn := range e.conns {
			if id == srcID {
				continue
			}
			if _, err := conn.Write(size); err != nil {
				e.disconnect(id, conn)
				return err
			}
			for _, view := range pkt.Views() {
				if _, err := conn.Write(view); err != nil {
					e.disconnect(id, conn)
					return err
				}
			}
		}
	} else {
		e.camLock.RLock()
		id, ok := e.cam[dst]
		if !ok {
			e.camLock.RUnlock()
			return nil
		}
		e.camLock.RUnlock()
		conn := e.conns[id]
		if _, err := conn.Write(size); err != nil {
			e.disconnect(id, conn)
			return err
		}
		for _, view := range pkt.Views() {
			if _, err := conn.Write(view); err != nil {
				e.disconnect(id, conn)
				return err
			}
		}
	}

	atomic.AddUint64(&e.Sent, uint64(pkt.Size()))
	return nil
}

func (e *Switch) disconnect(id int, conn net.Conn) {
	e.camLock.Lock()
	defer e.camLock.Unlock()

	for address, targetConn := range e.cam {
		if targetConn == id {
			delete(e.cam, address)
		}
	}
	_ = conn.Close()
	delete(e.conns, id)

	e.ipPool.Release(id)
}

func (e *Switch) rx(id int, conn net.Conn) error {
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

		buf := make([]byte, e.maxTransmissionUnit+header.EthernetMinimumSize)
		n, err = io.ReadFull(conn, buf[:size])
		if err != nil {
			return errors.Wrap(err, "cannot read packet from socket")
		}
		if n == 0 || n != size {
			return fmt.Errorf("unexpected size %d != %d", n, size)
		}

		if e.debug {
			packet := gopacket.NewPacket(buf[:size], layers.LayerTypeEthernet, gopacket.Default)
			log.Info(packet.String())
		}

		view := buffer.View(buf[:size])
		eth := header.Ethernet(view)
		vv := buffer.NewVectorisedView(len(view), []buffer.View{view})

		e.camLock.Lock()
		e.cam[eth.SourceAddress()] = id
		e.camLock.Unlock()

		if eth.DestinationAddress() != e.gateway.LinkAddress() {
			if err := e.tx(eth.DestinationAddress(), eth.SourceAddress(), &stack.PacketBuffer{
				Data: vv,
			}); err != nil {
				log.Error(err)
			}
		}
		if eth.DestinationAddress() == e.gateway.LinkAddress() || eth.DestinationAddress() == header.EthernetBroadcastAddress {
			vv.TrimFront(header.EthernetMinimumSize)
			e.gateway.DeliverNetworkPacket(
				eth.SourceAddress(),
				eth.DestinationAddress(),
				eth.Type(),
				&stack.PacketBuffer{
					Data: vv,
				},
			)
		}

		atomic.AddUint64(&e.Received, uint64(size))
	}
}
