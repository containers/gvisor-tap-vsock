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

const maxStreamPacketSize = 128 * 1024

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

	defer e.disconnect(id, conn)
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

type connTarget struct {
	id   int
	conn protocolConn
}

func (e *Switch) txPkt(pkt *stack.PacketBuffer) error {
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

		e.connLock.Lock()
		targets := make([]connTarget, 0, len(e.conns))
		for id, conn := range e.conns {
			if id != srcID {
				targets = append(targets, connTarget{id, conn})
			}
		}
		e.connLock.Unlock()

		for _, t := range targets {
			err := e.txBuf(t.conn, buf)
			if err != nil {
				e.disconnect(t.id, t.conn)
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

		e.connLock.Lock()
		conn, ok := e.conns[id]
		e.connLock.Unlock()
		if !ok {
			return nil
		}

		err := e.txBuf(conn, buf)
		if err != nil {
			e.disconnect(id, conn)
			return err
		}
		atomic.AddUint64(&e.Sent, uint64(size))
	}
	return nil
}

func (e *Switch) txBuf(conn protocolConn, buf []byte) error {
	e.writeLock.Lock()
	defer e.writeLock.Unlock()

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
			return err
		}
		return nil
	}
}

func (e *Switch) disconnect(id int, conn net.Conn) {
	e.connLock.Lock()
	defer e.connLock.Unlock()

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
	buf := make([]byte, maxStreamPacketSize)
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

func validateStreamPacketSize(size int) (err error) {
	if size < 0 || size > maxStreamPacketSize {
		err = fmt.Errorf("invalid packet size: %d is negative or exceeds maximum %d", size, maxStreamPacketSize)
	}
	return err
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
		if err := validateStreamPacketSize(size); err != nil {
			return err
		}

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

	if eth.Type() == ipv6.ProtocolNumber && len(buf) >= header.EthernetMinimumSize+header.IPv6MinimumSize {
		networkLayer := header.IPv6(buf[header.EthernetMinimumSize:])
		// Guard against a lying PayloadLength: networkLayer.Payload() slices
		// using that field and would panic if it exceeds the frame we received.
		if networkLayer.TransportProtocol() == header.ICMPv6ProtocolNumber &&
			int(networkLayer.PayloadLength()) <= len(networkLayer)-header.IPv6MinimumSize {
			payload := networkLayer.Payload()
			if len(payload) >= header.ICMPv6MinimumSize {
				transportLayer := header.ICMPv6(payload)
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
										uint8(prefixLen), //nolint:gosec
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
