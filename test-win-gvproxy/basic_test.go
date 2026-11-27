//go:build windows

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var testTimeout = 30 * time.Second

var _ = Describe("gvproxy", func() {
	It("prints its version", func() {
		output, err := exec.Command(gvproxyBinary, "-version").CombinedOutput()
		Expect(err).NotTo(HaveOccurred())
		Expect(string(output)).To(ContainSubstring("gvproxy version"))
	})

	It("starts and serves its services API over TCP", func() {
		apiPort, err := freePort()
		Expect(err).NotTo(HaveOccurred())
		servicesPort, err := freePort()
		Expect(err).NotTo(HaveOccurred())

		logPath := filepath.Join(tmpDir, "gvproxy.log")
		pidPath := filepath.Join(tmpDir, "gvproxy.pid")
		cmd := exec.Command(
			gvproxyBinary,
			"-debug",
			"-log-file", logPath,
			"-pid-file", pidPath,
			"-listen", fmt.Sprintf("tcp://127.0.0.1:%d", apiPort),
			"-services", fmt.Sprintf("tcp://127.0.0.1:%d", servicesPort),
		)

		var output bytes.Buffer
		cmd.Stdout = &output
		cmd.Stderr = &output
		Expect(cmd.Start()).To(Succeed())
		DeferCleanup(func() {
			if cmd.Process == nil {
				return
			}
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		})

		client := &http.Client{Timeout: 2 * time.Second}
		Eventually(func(g Gomega) {
			resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/stats", servicesPort))
			g.Expect(err).NotTo(HaveOccurred())
			defer resp.Body.Close()
			g.Expect(resp.StatusCode).To(Equal(http.StatusOK))

			stats := map[string]interface{}{}
			g.Expect(json.NewDecoder(resp.Body).Decode(&stats)).To(Succeed())
			g.Expect(stats).NotTo(BeEmpty())

			pid, err := os.ReadFile(pidPath)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(string(pid)).NotTo(BeEmpty())
		}).WithTimeout(testTimeout).WithPolling(200 * time.Millisecond).Should(Succeed())

		logContents, err := os.ReadFile(logPath)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(logContents)).To(ContainSubstring("waiting for clients..."))
		Expect(output.String()).NotTo(ContainSubstring("gvproxy exiting"))
	})
})

func freePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		return 0, err
	}
	return port, nil
}
