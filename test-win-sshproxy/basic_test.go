// +build windows

package e2e

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	winio "github.com/Microsoft/go-winio"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var timeout = 1 * time.Minute

var _ = Describe("connectivity", func() {
	It("proxy exits as requested, without a kill", func() {
		err := startProxy()
		Expect(err).ShouldNot(HaveOccurred())

		var pid uint32
		for i := 0; i < 20; i++ {
			pid, _, err = readTid()
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		Expect(err).ShouldNot(HaveOccurred())
		proc, err := os.FindProcess(int(pid))
		Expect(err).ShouldNot(HaveOccurred())
		Expect(proc).ShouldNot(BeNil())
		err = stopProxy(true)
		Expect(err).ShouldNot(HaveOccurred())
	})

	It("proxies over a windows pipe", func() {
		err := startProxy()
		Expect(err).ShouldNot(HaveOccurred())
		defer stopProxy(false)
		httpClient := &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return winio.DialPipe(`\\.\pipe\fake_docker_engine`, &timeout)
				},
			},
		}

		Eventually(func(g Gomega) {
			resp, err := httpClient.Get("http://host/ping")
			g.Expect(err).ShouldNot(HaveOccurred())
			defer resp.Body.Close()

			g.Expect(resp.StatusCode).To(Equal(http.StatusOK))
			g.Expect(resp.ContentLength).To(Equal(int64(4)))

			reply := make([]byte, resp.ContentLength)
			_, err = io.ReadAtLeast(resp.Body, reply, len(reply))

			g.Expect(err).ShouldNot(HaveOccurred())
			g.Expect(string(reply)).To(Equal("pong"))

		}).Should(Succeed())

		err = stopProxy(true)
		Expect(err).ShouldNot(HaveOccurred())
	})

	It("windows event logs were created", func() {
		cmd := exec.Command("powershell", "-Command", "&{Get-WinEvent -ProviderName \".NET Runtime\" -MaxEvents 10 | Where-Object -Property Message -Match \"test:\"}")
		reader, err := cmd.StdoutPipe()
		Expect(err).ShouldNot(HaveOccurred())
		cmd.Start()
		output, err := io.ReadAll(reader)
		Expect(err).ShouldNot(HaveOccurred())
		cmd.Wait()
		Expect(strings.Contains(string(output), `[info ] test: Listening on: \\.\pipe\fake_docker_engine`)).Should(BeTrue())
		Expect(strings.Contains(string(output), `[debug] test: Socket forward established`)).Should(BeTrue())
	})
})
