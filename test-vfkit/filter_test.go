//go:build darwin

package e2evfkit

import (
	e2e "github.com/containers/gvisor-tap-vsock/test"
	"github.com/onsi/ginkgo/v2"
)

var _ = ginkgo.Describe("filter API with vfkit", func() {
	e2e.FilterAPITests(e2e.FilterTestProps{
		SSHExec:      helper.SSHExec,
		ServicesSock: servicesSock,
	})
})

var _ = ginkgo.Describe("filter observability with vfkit", func() {
	e2e.FilterObservabilityTests(e2e.FilterTestProps{
		SSHExec:      helper.SSHExec,
		ServicesSock: servicesSock,
	})
})

var _ = ginkgo.Describe("filter blocking with vfkit", func() {
	e2e.FilterBlockingTests(e2e.FilterTestProps{
		SSHExec:      helper.SSHExec,
		ServicesSock: servicesSock,
	})
})
