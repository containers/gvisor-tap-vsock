package e2e

import (
	"fmt"
	"net/http"
	"os/exec"
	"sort"
	"sync"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func iperf3Executable() string {
	for _, binary := range []string{"iperf3", "iperf3-darwin"} {
		path, err := exec.LookPath(binary)
		if err == nil && path != "" {
			return path
		}
	}
	return ""
}

var iperf3InstallOnce sync.Once

func ensureIperf3InVM(props BasicTestProps) {
	iperf3InstallOnce.Do(func() {
		_, err := props.SSHExec("which iperf3 || sudo rpm-ostree install --apply-live --assumeyes iperf3")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})
}

func PerfIperf3Tests(props BasicTestProps) {
	ginkgo.BeforeEach(func() {
		gomega.Expect(iperf3Executable()).NotTo(gomega.BeEmpty(), "iperf3 must be installed on the host")
		ensureIperf3InVM(props)
	})

	ginkgo.It("should measure TCP throughput from VM to host", func() {
		iperf3Path := iperf3Executable()
		server := exec.Command(iperf3Path, "-s", "-1") // #nosec G204
		gomega.Expect(server.Start()).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() { _ = server.Process.Kill() })

		out, err := props.SSHExec("/usr/bin/iperf3 -c host.containers.internal --json")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		result, err := ParseIperf3JSON(out)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		ginkgo.AddReportEntry("tcp_vm_to_host_sent", FormatMbps(result.End.SumSent.BitsPerSecond))
		ginkgo.AddReportEntry("tcp_vm_to_host_received", FormatMbps(result.End.SumReceived.BitsPerSecond))
	})

	ginkgo.It("should measure TCP throughput from host to VM", func() {
		iperf3Path := iperf3Executable()
		server := exec.Command(iperf3Path, "-s", "-1") // #nosec G204
		gomega.Expect(server.Start()).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() { _ = server.Process.Kill() })

		out, err := props.SSHExec("/usr/bin/iperf3 -c host.containers.internal -R --json")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		result, err := ParseIperf3JSON(out)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		ginkgo.AddReportEntry("tcp_host_to_vm_sent", FormatMbps(result.End.SumSent.BitsPerSecond))
		ginkgo.AddReportEntry("tcp_host_to_vm_received", FormatMbps(result.End.SumReceived.BitsPerSecond))
	})

	ginkgo.It("should measure UDP throughput from VM to host", func() {
		iperf3Path := iperf3Executable()
		server := exec.Command(iperf3Path, "-s", "-1") // #nosec G204
		gomega.Expect(server.Start()).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() { _ = server.Process.Kill() })

		out, err := props.SSHExec("/usr/bin/iperf3 -c host.containers.internal -u --json")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		result, err := ParseIperf3JSON(out)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		ginkgo.AddReportEntry("udp_vm_to_host_sent", FormatMbps(result.End.SumSent.BitsPerSecond))
		ginkgo.AddReportEntry("udp_vm_to_host_lost_pct", fmt.Sprintf("%.2f%%", result.End.SumSent.LostPercent))
	})

	ginkgo.It("should measure UDP throughput from host to VM", func() {
		iperf3Path := iperf3Executable()
		server := exec.Command(iperf3Path, "-s", "-1") // #nosec G204
		gomega.Expect(server.Start()).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() { _ = server.Process.Kill() })

		out, err := props.SSHExec("/usr/bin/iperf3 -c host.containers.internal -R -u --json")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		result, err := ParseIperf3JSON(out)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		ginkgo.AddReportEntry("udp_host_to_vm_sent", FormatMbps(result.End.SumSent.BitsPerSecond))
		ginkgo.AddReportEntry("udp_host_to_vm_lost_pct", fmt.Sprintf("%.2f%%", result.End.SumSent.LostPercent))
	})
}

func startIperf3ServerInVM(props BasicTestProps) {
	_, _ = props.SSHExec("kill $(cat /tmp/iperf3.pid) 2>/dev/null; sleep 0.5")
	_, err := props.SSHExec("/usr/bin/iperf3 --server --daemon --pidfile /tmp/iperf3.pid")
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
}

func exposeTCPAndUDP(client interface {
	Expose(req *types.ExposeRequest) error
	Unexpose(req *types.UnexposeRequest) error
}, local, remote string) {
	gomega.Expect(client.Expose(&types.ExposeRequest{
		Local: local, Remote: remote, Protocol: types.TCP,
	})).To(gomega.Succeed())
	gomega.Expect(client.Expose(&types.ExposeRequest{
		Local: local, Remote: remote, Protocol: types.UDP,
	})).To(gomega.Succeed())
}

func unexposeTCPAndUDP(client interface {
	Unexpose(req *types.UnexposeRequest) error
}, local string) {
	_ = client.Unexpose(&types.UnexposeRequest{Local: local, Protocol: types.TCP})
	_ = client.Unexpose(&types.UnexposeRequest{Local: local, Protocol: types.UDP})
}

func PerfIperf3PortForwardedTests(props BasicTestProps) {
	ginkgo.BeforeEach(func() {
		gomega.Expect(iperf3Executable()).NotTo(gomega.BeEmpty(), "iperf3 must be installed on the host")
		gomega.Expect(props.GvproxyAPIClient).NotTo(gomega.BeNil(), "GvproxyAPIClient is required")
		ensureIperf3InVM(props)
	})

	ginkgo.It("should measure TCP throughput host to VM via port forwarding", func() {
		client := props.GvproxyAPIClient()
		gomega.Expect(client.Expose(&types.ExposeRequest{
			Local:    "127.0.0.1:5201",
			Remote:   "192.168.127.2:5201",
			Protocol: types.TCP,
		})).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() {
			_ = client.Unexpose(&types.UnexposeRequest{Local: "127.0.0.1:5201", Protocol: types.TCP})
		})

		startIperf3ServerInVM(props)
		ginkgo.DeferCleanup(func() { _, _ = props.SSHExec("kill $(cat /tmp/iperf3.pid) 2>/dev/null") })

		iperf3Path := iperf3Executable()
		out, err := exec.Command(iperf3Path, "-c", "127.0.0.1", "--json").Output() // #nosec G204
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		result, err := ParseIperf3JSON(out)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		ginkgo.AddReportEntry("tcp_fwd_host_to_vm_sent", FormatMbps(result.End.SumSent.BitsPerSecond))
		ginkgo.AddReportEntry("tcp_fwd_host_to_vm_received", FormatMbps(result.End.SumReceived.BitsPerSecond))
	})

	ginkgo.It("should measure TCP throughput VM to host via port forwarding", func() {
		client := props.GvproxyAPIClient()
		gomega.Expect(client.Expose(&types.ExposeRequest{
			Local:    "127.0.0.1:5201",
			Remote:   "192.168.127.2:5201",
			Protocol: types.TCP,
		})).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() {
			_ = client.Unexpose(&types.UnexposeRequest{Local: "127.0.0.1:5201", Protocol: types.TCP})
		})

		startIperf3ServerInVM(props)
		ginkgo.DeferCleanup(func() { _, _ = props.SSHExec("kill $(cat /tmp/iperf3.pid) 2>/dev/null") })

		iperf3Path := iperf3Executable()
		out, err := exec.Command(iperf3Path, "-c", "127.0.0.1", "-R", "--json").Output() // #nosec G204
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		result, err := ParseIperf3JSON(out)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		ginkgo.AddReportEntry("tcp_fwd_vm_to_host_sent", FormatMbps(result.End.SumSent.BitsPerSecond))
		ginkgo.AddReportEntry("tcp_fwd_vm_to_host_received", FormatMbps(result.End.SumReceived.BitsPerSecond))
	})

	ginkgo.It("should measure UDP throughput host to VM via port forwarding", func() {
		client := props.GvproxyAPIClient()
		exposeTCPAndUDP(client, "127.0.0.1:5201", "192.168.127.2:5201")
		ginkgo.DeferCleanup(func() { unexposeTCPAndUDP(client, "127.0.0.1:5201") })

		startIperf3ServerInVM(props)
		ginkgo.DeferCleanup(func() { _, _ = props.SSHExec("kill $(cat /tmp/iperf3.pid) 2>/dev/null") })

		iperf3Path := iperf3Executable()
		out, err := exec.Command(iperf3Path, "-c", "127.0.0.1", "-u", "--length", "9216", "--json").Output() // #nosec G204
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		result, err := ParseIperf3JSON(out)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		ginkgo.AddReportEntry("udp_fwd_host_to_vm_sent", FormatMbps(result.End.SumSent.BitsPerSecond))
		ginkgo.AddReportEntry("udp_fwd_host_to_vm_lost_pct", fmt.Sprintf("%.2f%%", result.End.SumSent.LostPercent))
	})

	ginkgo.It("should measure UDP throughput VM to host via port forwarding", func() {
		client := props.GvproxyAPIClient()
		exposeTCPAndUDP(client, "127.0.0.1:5201", "192.168.127.2:5201")
		ginkgo.DeferCleanup(func() { unexposeTCPAndUDP(client, "127.0.0.1:5201") })

		startIperf3ServerInVM(props)
		ginkgo.DeferCleanup(func() { _, _ = props.SSHExec("kill $(cat /tmp/iperf3.pid) 2>/dev/null") })

		iperf3Path := iperf3Executable()
		out, err := exec.Command(iperf3Path, "-c", "127.0.0.1", "-u", "-R", "--length", "9216", "--json").Output() // #nosec G204
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		result, err := ParseIperf3JSON(out)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		ginkgo.AddReportEntry("udp_fwd_vm_to_host_sent", FormatMbps(result.End.SumSent.BitsPerSecond))
		ginkgo.AddReportEntry("udp_fwd_vm_to_host_lost_pct", fmt.Sprintf("%.2f%%", result.End.SumSent.LostPercent))
	})
}

func PerfLatencyTests(props BasicTestProps) {
	ginkgo.It("should measure ICMP latency to gateway", func() {
		out, err := props.SSHExec("ping -c 50 -i 0.1 192.168.127.1")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		stats, err := ParsePingStats(string(out))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		ginkgo.AddReportEntry("ping_gateway_min_ms", fmt.Sprintf("%.3f", stats.Min))
		ginkgo.AddReportEntry("ping_gateway_avg_ms", fmt.Sprintf("%.3f", stats.Avg))
		ginkgo.AddReportEntry("ping_gateway_max_ms", fmt.Sprintf("%.3f", stats.Max))
		ginkgo.AddReportEntry("ping_gateway_mdev_ms", fmt.Sprintf("%.3f", stats.Mdev))
	})

	ginkgo.It("should measure ICMP latency to external host via NAT", func() {
		out, err := props.SSHExec("ping -c 20 -i 0.2 -W 5 1.1.1.1")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		stats, err := ParsePingStats(string(out))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		ginkgo.AddReportEntry("ping_external_min_ms", fmt.Sprintf("%.3f", stats.Min))
		ginkgo.AddReportEntry("ping_external_avg_ms", fmt.Sprintf("%.3f", stats.Avg))
		ginkgo.AddReportEntry("ping_external_max_ms", fmt.Sprintf("%.3f", stats.Max))
		ginkgo.AddReportEntry("ping_external_mdev_ms", fmt.Sprintf("%.3f", stats.Mdev))
	})
}

func PerfDNSTests(props BasicTestProps) {
	ginkgo.It("should measure internal DNS resolution latency", func() {
		out, err := props.SSHExec("for i in $(seq 1 100); do dig +noall +stats @192.168.127.1 host.containers.internal 2>&1; done")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		times, err := ParseDNSQueryTimes(string(out))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		sort.Ints(times.Times)
		p95idx := int(float64(len(times.Times)) * 0.95)
		if p95idx >= len(times.Times) {
			p95idx = len(times.Times) - 1
		}

		ginkgo.AddReportEntry("dns_internal_avg_ms", fmt.Sprintf("%.1f", times.Avg))
		ginkgo.AddReportEntry("dns_internal_p95_ms", fmt.Sprintf("%d", times.Times[p95idx]))
		ginkgo.AddReportEntry("dns_internal_max_ms", fmt.Sprintf("%d", times.Times[len(times.Times)-1]))
	})

	ginkgo.It("should measure external DNS resolution latency", func() {
		out, err := props.SSHExec("for i in $(seq 1 10); do dig +noall +stats @192.168.127.1 redhat.com 2>&1; done")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		times, err := ParseDNSQueryTimes(string(out))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		sort.Ints(times.Times)

		ginkgo.AddReportEntry("dns_external_avg_ms", fmt.Sprintf("%.1f", times.Avg))
		ginkgo.AddReportEntry("dns_external_max_ms", fmt.Sprintf("%d", times.Times[len(times.Times)-1]))
	})
}

func PerfPortForwardingTests(props BasicTestProps) {
	ginkgo.It("should measure port forwarding setup and teardown latency", func() {
		gomega.Expect(props.GvproxyAPIClient).NotTo(gomega.BeNil(), "GvproxyAPIClient is required")

		client := props.GvproxyAPIClient()
		const iterations = 50
		exposeTimes := make([]time.Duration, 0, iterations)
		unexposeTimes := make([]time.Duration, 0, iterations)

		for i := 0; i < iterations; i++ {
			port := fmt.Sprintf("127.0.0.1:%d", 10000+i)

			start := time.Now()
			err := client.Expose(&types.ExposeRequest{
				Local:  port,
				Remote: "192.168.127.2:8080",
			})
			exposeTimes = append(exposeTimes, time.Since(start))
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			start = time.Now()
			err = client.Unexpose(&types.UnexposeRequest{
				Local: port,
			})
			unexposeTimes = append(unexposeTimes, time.Since(start))
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		}

		exposeAvg := avgDuration(exposeTimes)
		unexposeAvg := avgDuration(unexposeTimes)
		exposeP95 := percentileDuration(exposeTimes, 0.95)
		unexposeP95 := percentileDuration(unexposeTimes, 0.95)

		ginkgo.AddReportEntry("expose_avg_us", fmt.Sprintf("%d", exposeAvg.Microseconds()))
		ginkgo.AddReportEntry("expose_p95_us", fmt.Sprintf("%d", exposeP95.Microseconds()))
		ginkgo.AddReportEntry("unexpose_avg_us", fmt.Sprintf("%d", unexposeAvg.Microseconds()))
		ginkgo.AddReportEntry("unexpose_p95_us", fmt.Sprintf("%d", unexposeP95.Microseconds()))
	})
}

func PerfIperf3ParallelTests(props BasicTestProps) {
	ginkgo.BeforeEach(func() {
		gomega.Expect(iperf3Executable()).NotTo(gomega.BeEmpty(), "iperf3 must be installed on the host")
		ensureIperf3InVM(props)
	})

	for _, streams := range []int{1, 4, 8} {
		streams := streams
		ginkgo.It(fmt.Sprintf("should measure TCP throughput with %d parallel streams", streams), func() {
			iperf3Path := iperf3Executable()
			server := exec.Command(iperf3Path, "-s", "-1") // #nosec G204
			gomega.Expect(server.Start()).To(gomega.Succeed())
			ginkgo.DeferCleanup(func() { _ = server.Process.Kill() })

			out, err := props.SSHExec(fmt.Sprintf("/usr/bin/iperf3 -c host.containers.internal -P %d --json", streams))
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			result, err := ParseIperf3JSON(out)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			ginkgo.AddReportEntry(fmt.Sprintf("tcp_%d_streams_sent", streams), FormatMbps(result.End.SumSent.BitsPerSecond))
			ginkgo.AddReportEntry(fmt.Sprintf("tcp_%d_streams_received", streams), FormatMbps(result.End.SumReceived.BitsPerSecond))
		})
	}
}

func PerfIperf3PayloadTests(props BasicTestProps) {
	ginkgo.BeforeEach(func() {
		gomega.Expect(iperf3Executable()).NotTo(gomega.BeEmpty(), "iperf3 must be installed on the host")
		ensureIperf3InVM(props)
	})

	for _, length := range []int{128, 512, 1460, 9216} {
		length := length
		ginkgo.It(fmt.Sprintf("should measure UDP throughput with %d byte payload", length), func() {
			iperf3Path := iperf3Executable()
			server := exec.Command(iperf3Path, "-s", "-1") // #nosec G204
			gomega.Expect(server.Start()).To(gomega.Succeed())
			ginkgo.DeferCleanup(func() { _ = server.Process.Kill() })

			out, err := props.SSHExec(fmt.Sprintf("/usr/bin/iperf3 -c host.containers.internal -u --length %d --json", length))
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			result, err := ParseIperf3JSON(out)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			ginkgo.AddReportEntry(fmt.Sprintf("udp_%d_bytes_sent", length), FormatMbps(result.End.SumSent.BitsPerSecond))
			ginkgo.AddReportEntry(fmt.Sprintf("udp_%d_bytes_lost_pct", length), fmt.Sprintf("%.2f%%", result.End.SumSent.LostPercent))
		})
	}
}

func PerfHTTPTests(props BasicTestProps) {
	ginkgo.It("should measure HTTP request rate through port forwarding", func() {
		gomega.Expect(props.GvproxyAPIClient).NotTo(gomega.BeNil(), "GvproxyAPIClient is required")

		client := props.GvproxyAPIClient()
		gomega.Expect(client.Expose(&types.ExposeRequest{
			Local:  "127.0.0.1:9090",
			Remote: "192.168.127.2:8080",
		})).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() {
			_ = client.Unexpose(&types.UnexposeRequest{Local: "127.0.0.1:9090"})
		})

		// Wait for the forwarded port to become reachable
		gomega.Eventually(func(g gomega.Gomega) {
			resp, err := http.Get("http://127.0.0.1:9090") // #nosec G107
			g.Expect(err).ShouldNot(gomega.HaveOccurred())
			resp.Body.Close()
			g.Expect(resp.StatusCode).To(gomega.Equal(http.StatusOK))
		}).WithTimeout(10 * time.Second).WithPolling(500 * time.Millisecond).Should(gomega.Succeed())

		const iterations = 200
		start := time.Now()
		for i := 0; i < iterations; i++ {
			resp, err := http.Get("http://127.0.0.1:9090") // #nosec G107
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			resp.Body.Close()
			gomega.Expect(resp.StatusCode).To(gomega.Equal(http.StatusOK))
		}
		elapsed := time.Since(start)

		reqPerSec := float64(iterations) / elapsed.Seconds()
		avgLatencyMs := elapsed.Seconds() / float64(iterations) * 1000

		ginkgo.AddReportEntry("http_fwd_requests_per_sec", fmt.Sprintf("%.1f", reqPerSec))
		ginkgo.AddReportEntry("http_fwd_avg_latency_ms", fmt.Sprintf("%.2f", avgLatencyMs))
	})
}

func avgDuration(durations []time.Duration) time.Duration {
	var total time.Duration
	for _, d := range durations {
		total += d
	}
	return total / time.Duration(len(durations))
}

func percentileDuration(durations []time.Duration, p float64) time.Duration {
	sorted := make([]time.Duration, len(durations))
	copy(sorted, durations)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	idx := int(float64(len(sorted)) * p)
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}
