package forwarder

import (
	"fmt"
	"net"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

var _ = ginkgo.Describe("exclusive listen on windows", ginkgo.Label("exclusive-bind"), func() {
	ginkgo.It("succeeds on a free port", func() {
		ln, err := listen("tcp", ":0")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		gomega.Expect(ln.Close()).To(gomega.Succeed())
	})

	// The other socket plays the role of e.g. vmware-hostd listening on
	// 0.0.0.0:443 while we expose the dual-stack ":443".
	ginkgo.DescribeTable("fails when the TCP port is already used by another socket",
		func(otherAddr string) {
			other, err := net.Listen("tcp4", otherAddr)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
			defer other.Close()
			port := other.Addr().(*net.TCPAddr).Port

			ln, err := listen("tcp", fmt.Sprintf(":%d", port))
			if err == nil {
				ln.Close()
			}
			gomega.Expect(err).Should(gomega.HaveOccurred(),
				"expected exclusive bind on :%d to fail while %s is in use", port, other.Addr())
		},
		ginkgo.Entry("IPv4 wildcard", "0.0.0.0:0"),
		ginkgo.Entry("IPv4 loopback", "127.0.0.1:0"),
	)
})
