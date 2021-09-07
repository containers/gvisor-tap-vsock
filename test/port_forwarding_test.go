package e2e

import (
	"context"
	"net"
	"net/http"

	gvproxyclient "github.com/containers/gvisor-tap-vsock/pkg/client"
	"github.com/containers/gvisor-tap-vsock/pkg/transport"
	"github.com/containers/gvisor-tap-vsock/pkg/types"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

var _ = Describe("port forwarding", func() {
	client := gvproxyclient.New(&http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", sock)
			},
		},
	}, "http://base")

	It("should reach a http server on the host", func() {
		ln, err := net.Listen("tcp", "127.0.0.1:9090")
		Expect(err).ShouldNot(HaveOccurred())
		defer ln.Close()

		mux := http.NewServeMux()
		mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
			_, _ = writer.Write([]byte("Hello from the host"))
		})
		go func() {
			if err := http.Serve(ln, mux); err != nil {
				log.Error(err)
			}
		}()

		out, err := sshExec("curl http://host.crc.testing:9090")
		Expect(err).ShouldNot(HaveOccurred())
		Expect(string(out)).To(ContainSubstring("Hello from the host"))
	})

	It("should reach a http server in the VM using dynamic port forwarding", func() {
		_, err := sshExec("sudo podman run --rm --name http-test -d -p 8080:80 -t docker.io/library/nginx:alpine")
		Expect(err).ShouldNot(HaveOccurred())
		defer func() {
			_, err := sshExec("sudo podman stop http-test")
			Expect(err).ShouldNot(HaveOccurred())
		}()

		_, err = net.Dial("tcp", "127.0.0.1:9090")
		Expect(err.Error()).To(HaveSuffix("connection refused"))

		Expect(client.Expose(&types.ExposeRequest{
			Local:  "127.0.0.1:9090",
			Remote: "192.168.127.2:8080",
		})).Should(Succeed())

		Eventually(func(g Gomega) {
			resp, err := http.Get("http://127.0.0.1:9090")
			g.Expect(err).ShouldNot(HaveOccurred())
			g.Expect(resp.StatusCode).To(Equal(http.StatusOK))
		}).Should(Succeed())

		Expect(client.Unexpose(&types.UnexposeRequest{
			Local: "127.0.0.1:9090",
		})).Should(Succeed())

		Eventually(func(g Gomega) {
			_, err = net.Dial("tcp", "127.0.0.1:9090")
			g.Expect(err.Error()).To(HaveSuffix("connection refused"))
		}).Should(Succeed())
	})

	It("should reach a http server in the VM using the tunneling of the daemon", func() {
		_, err := sshExec("sudo podman run --rm --name http-test -d -p 8080:80 -t docker.io/library/nginx:alpine")
		Expect(err).ShouldNot(HaveOccurred())
		defer func() {
			_, err := sshExec("sudo podman stop http-test")
			Expect(err).ShouldNot(HaveOccurred())
		}()

		httpClient := &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					conn, err := net.Dial("unix", sock)
					if err != nil {
						return nil, err
					}
					return conn, transport.Tunnel(conn, "192.168.127.2", 8080)
				},
			},
		}

		Eventually(func(g Gomega) {
			resp, err := httpClient.Get("http://placeholder/")
			g.Expect(err).ShouldNot(HaveOccurred())
			g.Expect(resp.StatusCode).To(Equal(http.StatusOK))
		}).Should(Succeed())
	})
})
