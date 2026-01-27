package e2e

import (
	"strings"

	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
)

func BasicIPv6ConnectivityTests(props BasicTestProps) {
	ginkgo.It("should configure the IPv6 address via DHCPv6", func() {
		out, err := props.SSHExec("ip -6 addr show dev $(ip route | grep '^default' | awk '{print $5}')")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		gomega.Expect(string(out)).To(gomega.MatchRegexp(`inet6 fd00::[0-9a-f]+/`))
	})

	ginkgo.It("should configure the IPv6 default route", func() {
		out, err := props.SSHExec("ip -6 route show default")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		gomega.Expect(string(out)).To(gomega.ContainSubstring("fe80::1"))
	})

	ginkgo.It("should configure IPv6 dns settings", func() {
		out, err := props.SSHExec("cat /etc/resolv.conf")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		gomega.Expect(string(out)).To(gomega.ContainSubstring("fd00::1"))
	})

	ginkgo.It("should have link-local IPv6 address", func() {
		out, err := props.SSHExec("ip -6 addr show scope link")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		gomega.Expect(string(out)).To(gomega.MatchRegexp(`inet6 fe80::[0-9a-f:]+/64`))
	})

	ginkgo.It("should ping6 the IPv6 gateway", func() {
		out, err := props.SSHExec("ping6 -c2 fd00::1")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		gomega.Expect(string(out)).To(gomega.ContainSubstring("2 packets transmitted, 2 received"))
	})
}

func BasicIPv6DNSTests(props BasicTestProps) {
	ginkgo.It("should resolve www.redhat.com AAAA record", func() {
		out, err := props.SSHExec("nslookup -query=AAAA www.redhat.com")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		gomega.Expect(string(out)).To(gomega.MatchRegexp(`Address:.*[0-9a-f]+:`))
	})

	ginkgo.It("should resolve gateway.containers.internal AAAA record", func() {
		out, err := props.SSHExec("nslookup -query=AAAA gateway.containers.internal")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		outStr := strings.ToLower(string(out))
		gomega.Expect(outStr).To(gomega.ContainSubstring("fd00::1"))
	})

	ginkgo.It("should resolve gateway.docker.internal AAAA record", func() {
		out, err := props.SSHExec("nslookup -query=AAAA gateway.docker.internal")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		outStr := strings.ToLower(string(out))
		gomega.Expect(outStr).To(gomega.ContainSubstring("fd00::1"))
	})
}
