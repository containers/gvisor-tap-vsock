package tap

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/containers/gvisor-tap-vsock/pkg/notification"
	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	log "github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type VirtualDevice interface {
	DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer)
	LinkAddress() tcpip.LinkAddress
	IP() string
	IPv6() string
	SubnetIPv6() string
}

type NetworkSwitch interface {
	DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer)
}

type Switch struct {
	Sent     uint64
	Received uint64

	debug bool

	nextConnID int
	conns      map[int]protocolConn
	connLock   sync.Mutex

	cam     map[tcpip.LinkAddress]int
	camLock sync.RWMutex

	writeLock sync.Mutex

	gateway VirtualDevice

	notificationSender *notification.NotificationSender
}

func NewSwitch(debug bool) *Switch {
	return &Switch{
		debug: debug,
		conns: make(map[int]protocolConn),
		cam:   make(map[tcpip.LinkAddress]int),
	}
}

func (e *Switch) CAM() map[string]int {
	e.camLock.RLock()
	defer e.camLock.RUnlock()
	ret := make(map[string]int)
	for address, port := range e.cam {
		ret[address.String()] = port
	}
	return ret
}

func (e *Switch) Connect(ep VirtualDevice) {
	e.gateway = ep
}

func (e *Switch) DeliverNetworkPacket(_ tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	if err := e.tx(pkt); err != nil {
		log.Error(err)
	}
}

func (e *Switch) Accept(ctx context.Context, rawConn net.Conn, protocol types.Protocol) error {
	conn := protocolConn{Conn: rawConn, protocolImpl: protocolImplementation(protocol)}
	log.Debugf("new connection from %s to %s", conn.RemoteAddr().String(), conn.LocalAddr().String())
	id, failed := e.connect(conn)
	if failed {
		log.Error("connection failed")
		return conn.Close()

	}

	defer func() {
		e.connLock.Lock()
		defer e.connLock.Unlock()
		e.disconnect(id, conn)
	}()
	if err := e.rx(ctx, id, conn); err != nil {
		err := fmt.Errorf("cannot receive packets from %s, disconnecting: %w", conn.RemoteAddr().String(), err)
		log.Error(err)
		return err
	}
	return nil
}

func (e *Switch) connect(conn protocolConn) (int, bool) {
	e.connLock.Lock()
	defer e.connLock.Unlock()

	id := e.nextConnID
	e.nextConnID++

	e.conns[id] = conn
	return id, false
}

func (e *Switch) tx(pkt *stack.PacketBuffer) error {
	return e.txPkt(pkt)
}

func (e *Switch) txPkt(pkt *stack.PacketBuffer) error {
	e.writeLock.Lock()
	defer e.writeLock.Unlock()

	e.connLock.Lock()
	defer e.connLock.Unlock()

	buf := pkt.ToView().AsSlice()
	eth := header.Ethernet(buf)
	dst := eth.DestinationAddress()
	src := eth.SourceAddress()

	size := pkt.Size()
	if size < 0 {
		return fmt.Errorf("packet size out of range")
	}
	if dst == header.EthernetBroadcastAddress || header.IsMulticastEthernetAddress(dst) {
		e.camLock.RLock()
		srcID, ok := e.cam[src]
		if !ok {
			srcID = -1
		}
		e.camLock.RUnlock()
		for id, conn := range e.conns {
			if id == srcID {
				continue
			}

			err := e.txBuf(id, conn, buf)
			if err != nil {
				return err
			}

			atomic.AddUint64(&e.Sent, uint64(size))
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
		err := e.txBuf(id, conn, buf)
		if err != nil {
			return err
		}
		atomic.AddUint64(&e.Sent, uint64(size))
	}
	return nil
}

func (e *Switch) txBuf(id int, conn protocolConn, buf []byte) error {
	if conn.protocolImpl.Stream() {
		size := conn.protocolImpl.(streamProtocol).Buf()
		conn.protocolImpl.(streamProtocol).Write(size, len(buf))
		buf = append(size, buf...)
	}
	for {
		if _, err := conn.Write(buf); err != nil {
			if errors.Is(err, syscall.ENOBUFS) {
				// socket buffer can be full keep retrying sending the same data
				// again until it works or we get a different error
				// https://github.com/containers/gvisor-tap-vsock/issues/367
				continue
			}
			e.disconnect(id, conn)
			return err
		}
		return nil
	}
}

func (e *Switch) disconnect(id int, conn net.Conn) {
	e.camLock.Lock()
	defer e.camLock.Unlock()

	for address, targetConn := range e.cam {
		if targetConn == id {
			if e.notificationSender != nil {
				e.notificationSender.Send(types.NotificationMessage{
					NotificationType: types.ConnectionClosed,
					MacAddress:       address.String(),
				})
			}
			delete(e.cam, address)
		}
	}
	_ = conn.Close()
	delete(e.conns, id)
}

func (e *Switch) rx(ctx context.Context, id int, conn protocolConn) error {
	if conn.protocolImpl.Stream() {
		return e.rxStream(ctx, id, conn, conn.protocolImpl.(streamProtocol))
	}
	return e.rxNonStream(ctx, id, conn)
}

func (e *Switch) rxNonStream(ctx context.Context, id int, conn net.Conn) error {
	bufSize := 1024 * 128
	buf := make([]byte, bufSize)
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		default:
			// passthrough
		}
		n, err := conn.Read(buf)
		if err != nil {
			return fmt.Errorf("cannot read size from socket: %w", err)
		}
		e.rxBuf(ctx, id, buf[:n])
	}
	return nil
}

func (e *Switch) rxStream(ctx context.Context, id int, conn net.Conn, sProtocol streamProtocol) error {
	reader := bufio.NewReader(conn)
	sizeBuf := sProtocol.Buf()
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		default:
			// passthrough
		}
		_, err := io.ReadFull(reader, sizeBuf)
		if err != nil {
			return fmt.Errorf("cannot read size from socket: %w", err)
		}
		size := sProtocol.Read(sizeBuf)

		buf := make([]byte, size)
		_, err = io.ReadFull(reader, buf)
		if err != nil {
			return fmt.Errorf("cannot read packet from socket: %w", err)
		}
		e.rxBuf(ctx, id, buf)
	}
	return nil
}

func (e *Switch) rxBuf(_ context.Context, id int, buf []byte) {
	if e.debug {
		packet := gopacket.NewPacket(buf, layers.LayerTypeEthernet, gopacket.Default)
		log.Info(packet.String())
	}

	eth := header.Ethernet(buf)

	e.camLock.Lock()
	_, exists := e.cam[eth.SourceAddress()]
	e.cam[eth.SourceAddress()] = id
	e.camLock.Unlock()

	if !exists && e.notificationSender != nil {
		e.notificationSender.Send(types.NotificationMessage{
			NotificationType: types.ConnectionEstablished,
			MacAddress:       eth.SourceAddress().String(),
		})
	}

	if eth.Type() == ipv6.ProtocolNumber {
		networkLayer := header.IPv6(buf[header.EthernetMinimumSize:])
		if networkLayer.TransportProtocol() == header.ICMPv6ProtocolNumber {
			transportLayer := header.ICMPv6(networkLayer.Payload())
			if transportLayer.Type() == header.ICMPv6RouterSolicit {

				if gatewayIPv6 := e.gateway.IPv6(); gatewayIPv6 != "" {
					// RFC 4861: Source Address MUST be the link-local address assigned to the interface from which this message is sent
					linkLocalAddr := tcpip.AddrFrom16Slice(
						net.ParseIP("fe80::1").To16(),
					)
					ndpOpts := header.NDPOptionsSerializer{
						header.NDPSourceLinkLayerAddressOption(e.gateway.LinkAddress()),
					}
					if subnetIPv6 := e.gateway.SubnetIPv6(); subnetIPv6 != "" {
						_, ipnet, err := net.ParseCIDR(subnetIPv6)
						if err == nil {
							prefixLen, _ := ipnet.Mask.Size()
							ndpOpts = append(
								ndpOpts,
								makePrefixInfo(
									uint8(prefixLen),
									ipnet.IP.To16(),
									86400,
									14400,
								),
							)
						}
					}
					routerAdvertisement, err := raBuf(
						e.gateway.LinkAddress(),
						eth.SourceAddress(),
						linkLocalAddr,
						1000,
						true,
						true,
						0,
						ndpOpts,
					)
					if err != nil {
						log.Error(err)
					} else {
						if err := e.tx(routerAdvertisement); err != nil {
							log.Error(err)
						}
						routerAdvertisement.DecRef()
					}
				}
			}
		}
	}

	if eth.DestinationAddress() != e.gateway.LinkAddress() {
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(buf),
		})
		if err := e.tx(pkt); err != nil {
			log.Error(err)
		}
		pkt.DecRef()
	}
	if eth.DestinationAddress() == e.gateway.LinkAddress() ||
		eth.DestinationAddress() == header.EthernetBroadcastAddress ||
		header.IsMulticastEthernetAddress(eth.DestinationAddress()) {

		data := buffer.MakeWithData(buf)
		data.TrimFront(header.EthernetMinimumSize)
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: data,
		})
		e.gateway.DeliverNetworkPacket(eth.Type(), pkt)
		pkt.DecRef()
	}

	atomic.AddUint64(&e.Received, uint64(len(buf)))
}

func protocolImplementation(protocol types.Protocol) protocol {
	switch protocol {
	case types.QemuProtocol:
		return &qemuProtocol{}
	case types.BessProtocol:
		return &bessProtocol{}
	case types.VfkitProtocol:
		return &vfkitProtocol{}
	default:
		return &hyperkitProtocol{}
	}
}

func (e *Switch) SetNotificationSender(notificationSender *notification.NotificationSender) {
	e.notificationSender = notificationSender
}

// makePrefixInfo creates an NDP Prefix Information option per RFC 4861 section 4.6.2.
// Layout (30 bytes after type/length header):
//   - [0]:     Prefix Length (bits)
//   - [1]:     Flags: bit 7 = OnLink (L), bit 6 = Autonomous (A)
//   - [2:6]:   Valid Lifetime (seconds, big-endian)
//   - [6:10]:  Preferred Lifetime (seconds, big-endian)
//   - [10:14]: Reserved
//   - [14:30]: Prefix (16 bytes IPv6 address)
func makePrefixInfo(prefixLen uint8, prefix []byte, validLifetime, preferredLifetime uint32) header.NDPPrefixInformation {
	buf := [30]byte{}
	buf[0] = prefixLen
	buf[1] = (1 << 7) | (1 << 6) // OnLink=1, Autonomous=1
	binary.BigEndian.PutUint32(buf[2:], validLifetime)
	binary.BigEndian.PutUint32(buf[6:], preferredLifetime)
	copy(buf[14:], prefix)
	return header.NDPPrefixInformation(buf[:])
}
