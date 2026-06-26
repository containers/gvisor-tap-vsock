package e2eqemu

import (
	e2e "github.com/containers/gvisor-tap-vsock/test"
	"github.com/onsi/ginkgo/v2"
)

var _ = ginkgo.Describe("filter API with qemu", func() {
	e2e.FilterAPITests(e2e.FilterTestProps{
		SSHExec:      sshExec,
		ServicesSock: servicesSock,
	})
})

var _ = ginkgo.Describe("filter observability with qemu", func() {
	e2e.FilterObservabilityTests(e2e.FilterTestProps{
		SSHExec:      sshExec,
		ServicesSock: servicesSock,
	})
})

var _ = ginkgo.Describe("filter blocking with qemu", func() {
	e2e.FilterBlockingTests(e2e.FilterTestProps{
		SSHExec:      sshExec,
		ServicesSock: servicesSock,
	})
})
