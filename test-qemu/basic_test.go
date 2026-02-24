package e2eqemu

import (
	"github.com/containers/gvisor-tap-vsock/pkg/types"
	e2e "github.com/containers/gvisor-tap-vsock/test"
	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

var _ = ginkgo.Describe("connectivity with qemu", func() {
	e2e.BasicConnectivityTests(e2e.BasicTestProps{
		SSHExec: sshExec,
	})
})

var _ = ginkgo.Describe("dns with qemu", func() {
	e2e.BasicDNSTests(e2e.BasicTestProps{
		SSHExec: sshExec,
		Sock:    sock,
	})
})

var _ = ginkgo.Describe("dhcp with qemu", func() {
	e2e.BasicDHCPTests(e2e.BasicTestProps{
		SSHExec: sshExec,
		Sock:    sock,
	})
})

var _ = ginkgo.Describe("command-line format", func() {
	ginkgo.It("should convert Command to command line format", func() {
		command := types.NewGvproxyCommand()
		command.AddEndpoint("unix:///tmp/network.sock")
		command.AddServiceEndpoint("unix:///tmp/services.sock")
		command.Debug = true
		command.AddQemuSocket("tcp://0.0.0.0:1234")
		command.PidFile = "~/gv-pidfile.txt"
		command.LogFile = "~/gv.log"
		command.AddForwardUser("demouser")

		cmd := command.ToCmdline()
		gomega.Expect(cmd).To(gomega.Equal([]string{
			"-listen", "unix:///tmp/network.sock",
			"-services", "unix:///tmp/services.sock",
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

// TODO: Add back when we have own test runner for CI
var _ = ginkgo.Describe("ping with gvproxy", func() {
	// ginkgo.It("should succeed to ping a known domain", func() {
	// 	out, err := sshExec("ping -w2 crc.dev")
	// 	log.Infof("ping: %s", out)
	// 	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	// })
	ginkgo.It("should fail to ping an unknown domain", func() {
		out, err := sshExec("ping -w2 unknown.crc.dev")
		log.Infof("ping: %s", out)
		gomega.Expect(err).To(gomega.HaveOccurred())
	})
	// ginkgo.It("should succeed to ping a known IP", func() {
	// 	out, err := sshExec("ping -w2 1.1.1.1")
	// 	log.Infof("ping: %s", out)
	// 	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	// })
	ginkgo.It("should fail to ping an unknown IP", func() {
		out, err := sshExec("ping -w2 7.7.7.7")
		log.Infof("ping: %s", out)
		gomega.Expect(err).To(gomega.HaveOccurred())
	})
	ginkgo.It("should succeed to ping an localhost", func() {
		out, err := sshExec("ping -w2 127.0.0.1")
		log.Infof("ping: %s", out)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})
})
