package e2evfkit

import (
	e2e "github.com/containers/gvisor-tap-vsock/test"
	"github.com/onsi/ginkgo"
)

var _ = ginkgo.Describe("connectivity with vfkit", func() {
	e2e.BasicConnectivityTests(e2e.BasicTestProps{
		SSHExec: sshExec,
	})
})

var _ = ginkgo.Describe("dns with vfkit", func() {
	e2e.BasicDNSTests(e2e.BasicTestProps{
		SSHExec: sshExec,
		Sock:    sock,
	})
})
