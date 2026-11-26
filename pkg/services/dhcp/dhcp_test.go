package dhcp

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/containers/gvisor-tap-vsock/pkg/tap"
	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/rfc1035label"
	"github.com/stretchr/testify/require"
)

type packetRecorder struct {
	net.PacketConn
	packet []byte
}

func (c *packetRecorder) WriteTo(packet []byte, _ net.Addr) (int, error) {
	c.packet = append([]byte(nil), packet...)
	return len(packet), nil
}

func TestHandlerSearchDomainsFitPacketSize(t *testing.T) {
	domains := make([]string, 62)
	for i := range domains {
		domains[i] = fmt.Sprintf("service-%02d.example.test", i)
	}

	tests := []struct {
		name       string
		option     *dhcpv4.Option
		mtu        int
		packetSize int
		trimmed    bool
	}{
		{name: "no maximum size", mtu: 1500, packetSize: 576, trimmed: true},
		{name: "minimum maximum size", option: optionPtr(dhcpv4.OptMaxMessageSize(576)), mtu: 1500, packetSize: 576, trimmed: true},
		{name: "client limits larger MTU", option: optionPtr(dhcpv4.OptMaxMessageSize(1024)), mtu: 1500, packetSize: 1024, trimmed: true},
		{name: "invalid maximum size", option: optionPtr(dhcpv4.OptMaxMessageSize(300)), mtu: 1500, packetSize: 576, trimmed: true},
		{name: "malformed maximum size", option: optionPtr(dhcpv4.Option{
			Code: dhcpv4.OptionMaximumDHCPMessageSize, Value: dhcpv4.String("x"),
		}), mtu: 1500, packetSize: 576, trimmed: true},
		{name: "MTU limits larger maximum", option: optionPtr(dhcpv4.OptMaxMessageSize(4096)), mtu: 1500, packetSize: 1500, trimmed: true},
		{name: "larger packets retain domains", option: optionPtr(dhcpv4.OptMaxMessageSize(4096)), mtu: 4000, packetSize: 4000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, messageType := range []dhcpv4.MessageType{dhcpv4.MessageTypeDiscover, dhcpv4.MessageTypeRequest} {
				t.Run(messageType.String(), func(t *testing.T) {
					packet, reply := handlerReply(t, domains, tt.mtu, messageType, tt.option)
					require.LessOrEqual(t, len(packet)+28, tt.packetSize, "reply must fit including IPv4/UDP headers")
					search := reply.DomainSearch()
					require.NotNil(t, search, "search option must contain complete, decodable names")
					require.NotEmpty(t, search.Labels)
					require.Equal(t, domains[:len(search.Labels)], search.Labels)
					if tt.trimmed {
						require.Less(t, len(search.Labels), len(domains))
						reply.UpdateOption(dhcpv4.OptDomainSearch(&rfc1035label.Labels{
							Labels: domains[:len(search.Labels)+1],
						}))
						require.Greater(t, len(reply.ToBytes())+28, tt.packetSize, "retain every domain that fits")
					} else {
						require.Equal(t, domains, search.Labels)
					}
				})
			}
		})
	}
}

func TestHandlerRetainsSmallSearchList(t *testing.T) {
	domains := []string{"example.test", "other.example.test"}
	_, reply := handlerReply(t, domains, 1500, dhcpv4.MessageTypeDiscover, nil)
	require.Equal(t, domains, reply.DomainSearch().Labels)
}

func TestHandlerOmitsSearchListWhenFirstDomainDoesNotFit(t *testing.T) {
	domain := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." +
		strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	packet, reply := handlerReply(t, []string{domain}, 550, dhcpv4.MessageTypeDiscover, nil)
	require.LessOrEqual(t, len(packet)+28, 550)
	require.Nil(t, reply.DomainSearch())
}

func handlerReply(t *testing.T, domains []string, mtu int, messageType dhcpv4.MessageType, option *dhcpv4.Option) ([]byte, *dhcpv4.DHCPv4) {
	t.Helper()
	configuration := &types.Configuration{
		Subnet: "192.0.2.0/24", GatewayIP: "192.0.2.1", MTU: mtu, DNSSearchDomains: domains,
	}
	pool, err := tap.NewIPPool(configuration.Subnet)
	require.NoError(t, err)
	require.NoError(t, pool.Reserve(configuration.GatewayIP, "gateway"))
	modifiers := []dhcpv4.Modifier{
		dhcpv4.WithHwAddr(net.HardwareAddr{0x02, 0, 0, 0, 0, 1}),
		dhcpv4.WithMessageType(messageType),
		dhcpv4.WithOption(dhcpv4.OptClientIdentifier([]byte{1, 0x02, 0, 0, 0, 0, 1})),
	}
	if option != nil {
		modifiers = append(modifiers, dhcpv4.WithOption(*option))
	}
	request, err := dhcpv4.New(modifiers...)
	require.NoError(t, err)
	conn := &packetRecorder{}
	handler(configuration, pool)(conn, &net.UDPAddr{}, request)
	reply, err := dhcpv4.FromBytes(conn.packet)
	require.NoError(t, err)
	require.Equal(t, net.ParseIP("192.0.2.1").To4(), reply.ServerIdentifier())
	require.Equal(t, []net.IP{net.ParseIP("192.0.2.1").To4()}, reply.DNS())
	if messageType == dhcpv4.MessageTypeDiscover {
		require.Equal(t, dhcpv4.MessageTypeOffer, reply.MessageType())
	} else {
		require.Equal(t, dhcpv4.MessageTypeAck, reply.MessageType())
	}
	return conn.packet, reply
}

func optionPtr(option dhcpv4.Option) *dhcpv4.Option {
	return &option
}
