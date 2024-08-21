package e2e

import (
	"context"
	"net"
	"net/http"

	gvproxyclient "github.com/containers/gvisor-tap-vsock/pkg/client"
	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
)

var _ = ginkgo.Describe("connectivity", func() {
	ginkgo.It("should configure the interface", func() {
		out, err := sshExec("ifconfig $(route | grep '^default' | grep -o '[^ ]*$')")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		gomega.Expect(string(out)).To(gomega.ContainSubstring("mtu 1500"))
		gomega.Expect(string(out)).To(gomega.ContainSubstring("inet 192.168.127.2"))
		gomega.Expect(string(out)).To(gomega.ContainSubstring("netmask 255.255.255.0"))
		gomega.Expect(string(out)).To(gomega.ContainSubstring("broadcast 192.168.127.255"))
	})

	ginkgo.It("should configure the default route", func() {
		out, err := sshExec("ip route show")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		gomega.Expect(string(out)).To(gomega.MatchRegexp(`default via 192\.168\.127\.1 dev (.*?) proto dhcp (src 192\.168\.127\.2 )?metric 100`))
	})

	ginkgo.It("should configure dns settings", func() {
		out, err := sshExec("cat /etc/resolv.conf")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		gomega.Expect(string(out)).To(gomega.ContainSubstring("nameserver 192.168.127.1"))
	})

	ginkgo.It("should ping the tap device", func() {
		out, err := sshExec("ping -c2 192.168.127.2")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		gomega.Expect(string(out)).To(gomega.ContainSubstring("2 packets transmitted, 2 received, 0% packet loss"))
	})

	ginkgo.It("should ping the gateway", func() {
		out, err := sshExec("ping -c2 192.168.127.1")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		gomega.Expect(string(out)).To(gomega.ContainSubstring("2 packets transmitted, 2 received, 0% packet loss"))
	})
})

var _ = ginkgo.Describe("dns", func() {
	ginkgo.It("should resolve redhat.com", func() {
		out, err := sshExec("nslookup redhat.com")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		gomega.Expect(string(out)).To(gomega.ContainSubstring("Address: 52.200.142.250"))
	})

	ginkgo.It("should resolve CNAME record for docs.crc.dev", func() {
		out, err := sshExec("nslookup -query=cname docs.crc.dev")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		gomega.Expect(string(out)).To(gomega.ContainSubstring("docs.crc.dev	canonical name = webredir.gandi.net."))
	})
	ginkgo.It("should resolve MX record for crc.dev", func() {
		out, err := sshExec("nslookup -query=mx crc.dev")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		gomega.Expect(string(out)).To(gomega.ContainSubstring("crc.dev	mail exchanger = 10 spool.mail.gandi.net."))
	})

	ginkgo.It("should resolve NS record for wikipedia.org", func() {
		out, err := sshExec("nslookup -query=ns wikipedia.org")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		gomega.Expect(string(out)).To(gomega.ContainSubstring("wikipedia.org	nameserver = ns0.wikimedia.org."))
	})
	ginkgo.It("should resolve IMAPS SRV record for crc.dev", func() {
		out, err := sshExec("nslookup -query=srv _imaps._tcp.crc.dev")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		gomega.Expect(string(out)).To(gomega.ContainSubstring(`_imaps._tcp.crc.dev	service = 0 1 993 mail.gandi.net.`))
	})
	ginkgo.It("should resolve TXT for crc.dev", func() {
		out, err := sshExec("nslookup -query=txt crc.dev")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		gomega.Expect(string(out)).To(gomega.ContainSubstring(`text = "v=spf1`))
	})

	ginkgo.It("should resolve gateway.containers.internal", func() {
		out, err := sshExec("nslookup gateway.containers.internal")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		gomega.Expect(string(out)).To(gomega.ContainSubstring("Address: 192.168.127.1"))
	})

	ginkgo.It("should resolve host.containers.internal", func() {
		out, err := sshExec("nslookup host.containers.internal")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		gomega.Expect(string(out)).To(gomega.ContainSubstring("Address: 192.168.127.254"))
	})

	ginkgo.It("should resolve dynamically added dns entry test.dynamic.internal", func() {
		client := gvproxyclient.New(&http.Client{
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
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
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

		out, err := sshExec("nslookup test.dynamic.internal")

		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		gomega.Expect(string(out)).To(gomega.ContainSubstring("Address: 192.168.127.254"))
	})

	ginkgo.It("should resolve recently added dns entry test.dynamic.internal", func() {
		client := gvproxyclient.New(&http.Client{
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
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
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

		err = client.AddDNS(&types.Zone{
			Name: "dynamic.internal.",
			Records: []types.Record{
				{
					Name: "test",
					IP:   net.ParseIP("192.168.127.253"),
				},
			},
		})
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

		out, err := sshExec("nslookup test.dynamic.internal")

		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		gomega.Expect(string(out)).To(gomega.ContainSubstring("Address: 192.168.127.253"))
	})

	ginkgo.It("should retain order of existing zone", func() {
		client := gvproxyclient.New(&http.Client{
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
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
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		gomega.Expect(string(out)).To(gomega.ContainSubstring("Address: 192.168.127.2"))

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
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		gomega.Expect(string(out)).To(gomega.ContainSubstring("Address: 192.168.127.2"))

		out, err = sshExec("nslookup gateway.testing")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		gomega.Expect(string(out)).To(gomega.ContainSubstring("Address: 192.168.127.1"))
	})
})

var _ = ginkgo.Describe("command-line format", func() {
	ginkgo.It("should convert Command to command line format", func() {
		command := types.NewGvproxyCommand()
		command.AddEndpoint("unix:///tmp/network.sock")
		command.Debug = true
		command.AddQemuSocket("tcp://0.0.0.0:1234")
		command.PidFile = "~/gv-pidfile.txt"
		command.LogFile = "~/gv.log"
		command.AddForwardUser("demouser")

		cmd := command.ToCmdline()
		gomega.Expect(cmd).To(gomega.Equal([]string{
			"-listen", "unix:///tmp/network.sock",
			"-debug",
			"-mtu", "1500",
			"-ssh-port", "2222",
			"-listen-qemu", "tcp://0.0.0.0:1234",
			"-forward-user", "demouser",
			"-pid-file", "~/gv-pidfile.txt",
			"-log-file", "~/gv.log",
		}))
	})
})
