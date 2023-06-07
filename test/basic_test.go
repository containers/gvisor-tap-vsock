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
			Name:      "dynamic.internal.",
			DefaultIP: net.ParseIP("192.168.127.253"),
		})
		Expect(err).ShouldNot(HaveOccurred())

		out, err := sshExec("nslookup test.dynamic.internal")

		Expect(err).ShouldNot(HaveOccurred())
		Expect(string(out)).To(ContainSubstring("Address: 192.168.127.253"))
	})
})
