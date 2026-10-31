package e2e

import (
	"strings"

	"github.com/onsi/ginkgo/v2"
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

	// The specs below open a real connection to the external IPv6 internet
	// through gvproxy's TCP forwarder (which dials the destination from the
	// host). Unlike the checks above, they depend on the host actually having
	// IPv6 egress, so they fail on an IPv4-only host/ISP. This is what proves
	// end-to-end IPv6 connectivity rather than just internal configuration.
	//
	// -6 forces IPv6 so there is no silent fallback to IPv4.

	ginkgo.It("should reach an external IPv6 host by literal address", func() {
		// Connect to Cloudflare's public resolver over its global IPv6 address.
		// This isolates IPv6 routing from DNS: no AAAA lookup is involved.
		// -k skips TLS verification since we connect by literal address.
		out, err := props.SSHExec("curl -6 -k -sS -o /dev/null -w '%{http_code}' --max-time 15 https://[2606:4700:4700::1111]")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		gomega.Expect(string(out)).To(gomega.MatchRegexp(`^[1-5][0-9]{2}$`))
	})

	ginkgo.It("should reach an external IPv6 host by name", func() {
		// Exercises the full path: AAAA resolution via gvproxy's DNS plus IPv6
		// routing to the resolved address.
		out, err := props.SSHExec("curl -6 -sS -o /dev/null -w '%{http_code}' --max-time 15 https://ipv6.google.com")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		gomega.Expect(string(out)).To(gomega.MatchRegexp(`^[1-5][0-9]{2}$`))
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
