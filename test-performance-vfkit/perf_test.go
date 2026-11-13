//go:build darwin

package e2e_performance_vfkit

import (
	e2e "github.com/containers/gvisor-tap-vsock/test"
	"github.com/onsi/ginkgo/v2"
)

var _ = ginkgo.Describe("iperf3 throughput", func() {
	e2e.PerfIperf3Tests(e2e.BasicTestProps{
		SSHExec: helper.SSHExec,
		Sock:    helper.Cfg.Sock,
	})
})

var _ = ginkgo.Describe("iperf3 throughput via port forwarding", func() {
	e2e.PerfIperf3PortForwardedTests(e2e.BasicTestProps{
		SSHExec:          helper.SSHExec,
		Sock:             helper.Cfg.Sock,
		GvproxyAPIClient: helper.NewGvproxyAPIClient,
	})
})

var _ = ginkgo.Describe("latency", func() {
	e2e.PerfLatencyTests(e2e.BasicTestProps{
		SSHExec: helper.SSHExec,
	})
})

var _ = ginkgo.Describe("DNS resolution latency", func() {
	e2e.PerfDNSTests(e2e.BasicTestProps{
		SSHExec: helper.SSHExec,
	})
})

var _ = ginkgo.Describe("port forwarding operations", func() {
	e2e.PerfPortForwardingTests(e2e.BasicTestProps{
		SSHExec:          helper.SSHExec,
		Sock:             helper.Cfg.Sock,
		GvproxyAPIClient: helper.NewGvproxyAPIClient,
	})
})

var _ = ginkgo.Describe("iperf3 parallel streams", func() {
	e2e.PerfIperf3ParallelTests(e2e.BasicTestProps{
		SSHExec: helper.SSHExec,
	})
})

var _ = ginkgo.Describe("iperf3 UDP payload sizes", func() {
	e2e.PerfIperf3PayloadTests(e2e.BasicTestProps{
		SSHExec: helper.SSHExec,
	})
})

var _ = ginkgo.Describe("HTTP request rate", func() {
	e2e.PerfHTTPTests(e2e.BasicTestProps{
		SSHExec:          helper.SSHExec,
		Sock:             helper.Cfg.Sock,
		GvproxyAPIClient: helper.NewGvproxyAPIClient,
	})
})
