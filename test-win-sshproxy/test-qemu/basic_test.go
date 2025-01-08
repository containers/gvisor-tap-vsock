//go:build windows
// +build windows

package e2e_win_qemu

import (
	"context"
	"io"
	"net"
	"net/http"
	"time"

	winio "github.com/Microsoft/go-winio"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var timeout = 1 * time.Minute

var _ = Describe("connectivity", func() {
	It("proxies over a windows pipe to call podman api", func() {
		httpClient := &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return winio.DialPipe(npipePodmanTestPath, &timeout)
				},
			},
		}

		Eventually(func(g Gomega) {
			resp, err := httpClient.Get("http://localhost/v4.0.2/libpod/info")
			g.Expect(err).ShouldNot(HaveOccurred())
			defer resp.Body.Close()

			g.Expect(resp.StatusCode).To(Equal(http.StatusOK))

			reply := make([]byte, 8)
			_, err = io.ReadAtLeast(resp.Body, reply, len(reply))

			g.Expect(err).ShouldNot(HaveOccurred())
			g.Expect(string(reply)).To(Equal("{\"host\":"))

		}).Should(Succeed())
	})
})
