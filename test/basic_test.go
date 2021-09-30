package e2e

import (
	"context"
	"net"
	"net/http"

	gvproxyclient "github.com/containers/gvisor-tap-vsock/pkg/client"
	"github.com/containers/gvisor-tap-vsock/pkg/types"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("connectivity", func() {
	It("should configure the interface", func() {
		out, err := sshExec("ifconfig $(route | grep '^default' | grep -o '[^ ]*$')")
		Expect(err).ShouldNot(HaveOccurred())
		Expect(string(out)).To(ContainSubstring("mtu 1500"))
		Expect(string(out)).To(ContainSubstring("inet 192.168.127.2"))
		Expect(string(out)).To(ContainSubstring("netmask 255.255.255.0"))
		Expect(string(out)).To(ContainSubstring("broadcast 192.168.127.255"))
	})

	It("should configure the default route", func() {
		out, err := sshExec("ip route show")
		Expect(err).ShouldNot(HaveOccurred())
		Expect(string(out)).To(MatchRegexp(`default via 192\.168\.127\.1 dev (.*?) proto dhcp (src 192\.168\.127\.2 )?metric 100`))
	})

	It("should configure dns settings", func() {
		out, err := sshExec("cat /etc/resolv.conf")
		Expect(err).ShouldNot(HaveOccurred())
		Expect(string(out)).To(ContainSubstring("nameserver 192.168.127.1"))
	})

	It("should ping the tap device", func() {
		out, err := sshExec("ping -c2 192.168.127.2")
		Expect(err).ShouldNot(HaveOccurred())
		Expect(string(out)).To(ContainSubstring("2 packets transmitted, 2 received, 0% packet loss"))
	})

	It("should ping the gateway", func() {
		out, err := sshExec("ping -c2 192.168.127.1")
		Expect(err).ShouldNot(HaveOccurred())
		Expect(string(out)).To(ContainSubstring("2 packets transmitted, 2 received, 0% packet loss"))
	})
})

var _ = Describe("dns", func() {
	It("should resolve redhat.com", func() {
		out, err := sshExec("nslookup redhat.com")
		Expect(err).ShouldNot(HaveOccurred())
		Expect(string(out)).To(ContainSubstring("Address: 52.200.142.250"))
	})

	It("should resolve CNAME record for www.wikipedia.org", func() {
		out, err := sshExec("nslookup -query=cname www.wikipedia.org")
		Expect(err).ShouldNot(HaveOccurred())
		Expect(string(out)).To(ContainSubstring("www.wikipedia.org	canonical name = dyna.wikimedia.org."))
	})
	It("should resolve MX record for wikipedia.org", func() {
		out, err := sshExec("nslookup -query=mx wikipedia.org")
		Expect(err).ShouldNot(HaveOccurred())
		Expect(string(out)).To(ContainSubstring("wikipedia.org	mail exchanger = 10 mx1001.wikimedia.org."))
	})

	It("should resolve NS record for wikipedia.org", func() {
		out, err := sshExec("nslookup -query=ns wikipedia.org")
		Expect(err).ShouldNot(HaveOccurred())
		Expect(string(out)).To(ContainSubstring("wikipedia.org	nameserver = ns0.wikimedia.org."))
	})
	It("should resolve LDAP SRV record for google.com", func() {
		out, err := sshExec("nslookup -query=srv _ldap._tcp.google.com")
		Expect(err).ShouldNot(HaveOccurred())
		Expect(string(out)).To(ContainSubstring(`_ldap._tcp.google.com	service = 5 0 389 ldap.google.com.`))
	})
	It("should resolve TXT for wikipedia.org", func() {
		out, err := sshExec("nslookup -query=txt wikipedia.org")
		Expect(err).ShouldNot(HaveOccurred())
		Expect(string(out)).To(ContainSubstring(`"v=spf1 include:wikimedia.org ~all"`))
	})

	It("should resolve gateway.containers.internal", func() {
		out, err := sshExec("nslookup gateway.containers.internal")
		Expect(err).ShouldNot(HaveOccurred())
		Expect(string(out)).To(ContainSubstring("Address: 192.168.127.1"))
	})

	It("should resolve host.containers.internal", func() {
		out, err := sshExec("nslookup host.containers.internal")
		Expect(err).ShouldNot(HaveOccurred())
		Expect(string(out)).To(ContainSubstring("Address: 192.168.127.254"))
	})

	It("should resolve dynamically added dns entry test.dynamic.internal", func() {
		client := gvproxyclient.New(&http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return net.Dial("unix", sock)
				},
			},
		}, "http://base")
		err := client.AddDNS(&types.Zone{
			Name: "dynamic.internal.",
			Records: []types.Record{
				{
					Name: "test",
					IP:   net.ParseIP("192.168.127.254"),
				},
			},
		})
		Expect(err).ShouldNot(HaveOccurred())

		out, err := sshExec("nslookup test.dynamic.internal")

		Expect(err).ShouldNot(HaveOccurred())
		Expect(string(out)).To(ContainSubstring("Address: 192.168.127.254"))
	})

	It("should resolve recently added dns entry test.dynamic.internal", func() {
		client := gvproxyclient.New(&http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return net.Dial("unix", sock)
				},
			},
		}, "http://base")
		err := client.AddDNS(&types.Zone{
			Name: "dynamic.internal.",
			Records: []types.Record{
				{
					Name: "test",
					IP:   net.ParseIP("192.168.127.254"),
				},
			},
		})
		Expect(err).ShouldNot(HaveOccurred())

		err = client.AddDNS(&types.Zone{
			Name: "dynamic.internal.",
			Records: []types.Record{
				{
					Name: "test",
					IP:   net.ParseIP("192.168.127.253"),
				},
			},
		})
		Expect(err).ShouldNot(HaveOccurred())

		out, err := sshExec("nslookup test.dynamic.internal")

		Expect(err).ShouldNot(HaveOccurred())
		Expect(string(out)).To(ContainSubstring("Address: 192.168.127.253"))
	})

	It("should retain order of existing zone", func() {
		client := gvproxyclient.New(&http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return net.Dial("unix", sock)
				},
			},
		}, "http://base")
		_ = client.AddDNS(&types.Zone{
			Name:      "dynamic.testing.",
			DefaultIP: net.ParseIP("192.168.127.2"),
		})
		_ = client.AddDNS(&types.Zone{
			Name: "testing.",
			Records: []types.Record{
				{
					Name: "host",
					IP:   net.ParseIP("192.168.127.3"),
				},
			},
		})
		out, err := sshExec("nslookup test.dynamic.internal")
		Expect(err).ShouldNot(HaveOccurred())
		Expect(string(out)).To(ContainSubstring("Address: 192.168.127.2"))

		_ = client.AddDNS(&types.Zone{
			Name: "testing.",
			Records: []types.Record{
				{
					Name: "gateway",
					IP:   net.ParseIP("192.168.127.1"),
				},
			},
		})
		out, err = sshExec("nslookup *.dynamic.testing")
		Expect(err).ShouldNot(HaveOccurred())
		Expect(string(out)).To(ContainSubstring("Address: 192.168.127.2"))

		out, err = sshExec("nslookup gateway.testing")
		Expect(err).ShouldNot(HaveOccurred())
		Expect(string(out)).To(ContainSubstring("Address: 192.168.127.1"))
	})

	It("should resolve ipv6", func() {
		out, err := sshExec("nslookup ipv6.google.com")
		Expect(err).ShouldNot(HaveOccurred())
		Expect(string(out)).To(ContainSubstring("Address: 2a00:1450:4007:810::200e"))
	})
})

var _ = Describe("ipv6", func() {
	It("tcp should work", func() {
		out, err := sshExec("curl ipv6.google.com")
		Expect(err).ShouldNot(HaveOccurred())
		Expect(string(out)).To(ContainSubstring("<!doctype html>"))
	})

	It("udp should work", func() {
		out, err := sshExec("dig ipv6.google.com @2001:4860:4860::8888")
		Expect(err).ShouldNot(HaveOccurred())
		Expect(string(out)).To(ContainSubstring("opcode: QUERY, status: NOERROR"))
	})
})

var _ = Describe("command-line format", func() {
	It("should convert Command to command line format", func() {
		command := types.NewGvproxyCommand()
		command.AddEndpoint("unix:///tmp/network.sock")
		command.Debug = true
		command.AddQemuSocket("tcp://0.0.0.0:1234")
		command.PidFile = "~/gv-pidfile.txt"
		command.AddForwardUser("demouser")

		cmd := command.ToCmdline()
		Expect(cmd).To(Equal([]string{
			"-listen", "unix:///tmp/network.sock",
			"-debug",
			"-mtu", "1500",
			"-ssh-port", "2222",
			"-listen-qemu", "tcp://0.0.0.0:1234",
			"-forward-user", "demouser",
			"-pid-file", "~/gv-pidfile.txt",
		}))
	})
})
