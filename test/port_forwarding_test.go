package e2e

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	gvproxyclient "github.com/containers/gvisor-tap-vsock/pkg/client"
	"github.com/containers/gvisor-tap-vsock/pkg/transport"
	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

var _ = ginkgo.Describe("port forwarding", func() {
	client := gvproxyclient.New(&http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", sock)
			},
		},
	}, "http://base")

	ginkgo.It("should reach a http server on the host", func() {
		ln, err := net.Listen("tcp", "127.0.0.1:9090")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		defer ln.Close()

		mux := http.NewServeMux()
		mux.HandleFunc("/", func(writer http.ResponseWriter, _ *http.Request) {
			_, _ = writer.Write([]byte("Hello from the host"))
		})
		go func() {
			s := &http.Server{
				Handler:      mux,
				ReadTimeout:  10 * time.Second,
				WriteTimeout: 10 * time.Second,
			}
			err := s.Serve(ln)
			if err != nil {
				log.Error(err)
			}
		}()

		out, err := sshExec("curl http://host.containers.internal:9090")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		gomega.Expect(string(out)).To(gomega.ContainSubstring("Hello from the host"))

		out, err = sshExec("curl http://host.docker.internal:9090")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		gomega.Expect(string(out)).To(gomega.ContainSubstring("Hello from the host"))
	})

	ginkgo.It("should reach a http server in the VM using dynamic port forwarding", func() {
		_, err := net.Dial("tcp", "127.0.0.1:9090")
		gomega.Expect(err).Should(gomega.HaveOccurred())
		gomega.Expect(err.Error()).To(gomega.HaveSuffix("connection refused"))

		gomega.Expect(client.Expose(&types.ExposeRequest{
			Local:  "127.0.0.1:9090",
			Remote: "192.168.127.2:8080",
		})).Should(gomega.Succeed())

		gomega.Eventually(func(g gomega.Gomega) {
			resp, err := http.Get("http://127.0.0.1:9090")
			g.Expect(err).ShouldNot(gomega.HaveOccurred())
			g.Expect(resp.StatusCode).To(gomega.Equal(http.StatusOK))
		}).Should(gomega.Succeed())

		gomega.Expect(client.Unexpose(&types.UnexposeRequest{
			Local: "127.0.0.1:9090",
		})).Should(gomega.Succeed())

		gomega.Eventually(func(g gomega.Gomega) {
			_, err = net.Dial("tcp", "127.0.0.1:9090")
			g.Expect(err).Should(gomega.HaveOccurred())
			g.Expect(err.Error()).To(gomega.HaveSuffix("connection refused"))
		}).Should(gomega.Succeed())
	})

	ginkgo.It("should reach a dns server in the VM using dynamic port forwarding", func() {
		gomega.Expect(client.Expose(&types.ExposeRequest{
			Local:    ":1053",
			Remote:   "192.168.127.2:53",
			Protocol: "udp",
		})).Should(gomega.Succeed())

		gomega.Eventually(func(g gomega.Gomega) {
			cmd := exec.Command("nslookup", "-timeout=1", "-port=1053", "foobar", "127.0.0.1")
			out, err := cmd.CombinedOutput()
			g.Expect(err).ShouldNot(gomega.HaveOccurred())
			g.Expect(string(out)).To(gomega.ContainSubstring("Address: 1.2.3.4"))
		}).Should(gomega.Succeed())

		gomega.Expect(client.Unexpose(&types.UnexposeRequest{
			Local:    ":1053",
			Protocol: "udp",
		})).Should(gomega.Succeed())
	})

	ginkgo.It("should reach a http server in the VM using the tunneling of the daemon", func() {
		httpClient := &http.Client{
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					conn, err := net.Dial("unix", sock)
					if err != nil {
						return nil, err
					}
					return conn, transport.Tunnel(conn, "192.168.127.2", 8080)
				},
			},
		}

		gomega.Eventually(func(g gomega.Gomega) {
			resp, err := httpClient.Get("http://placeholder/")
			g.Expect(err).ShouldNot(gomega.HaveOccurred())
			g.Expect(resp.StatusCode).To(gomega.Equal(http.StatusOK))
		}).Should(gomega.Succeed())
	})

	ginkgo.It("should reach a http server in the VM using dynamic port forwarding configured within the VM", func() {
		_, err := net.Dial("tcp", "127.0.0.1:9090")
		gomega.Expect(err).Should(gomega.HaveOccurred())
		gomega.Expect(err.Error()).To(gomega.HaveSuffix("connection refused"))

		_, err = sshExec(`curl http://gateway.containers.internal/services/forwarder/expose -X POST -d'{"local":":9090", "remote":":8080"}'`)
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

		gomega.Eventually(func(g gomega.Gomega) {
			resp, err := http.Get("http://127.0.0.1:9090")
			g.Expect(err).ShouldNot(gomega.HaveOccurred())
			g.Expect(resp.StatusCode).To(gomega.Equal(http.StatusOK))
		}).Should(gomega.Succeed())

		_, err = sshExec(`curl http://gateway.containers.internal/services/forwarder/unexpose -X POST -d'{"local":":9090"}'`)
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

		gomega.Eventually(func(g gomega.Gomega) {
			_, err = net.Dial("tcp", "127.0.0.1:9090")
			g.Expect(err).Should(gomega.HaveOccurred())
			g.Expect(err.Error()).To(gomega.HaveSuffix("connection refused"))
		}).Should(gomega.Succeed())
	})

	ginkgo.It("should reach rootless podman API using unix socket forwarding over ssh", func() {
		httpClient := &http.Client{
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return net.Dial("unix", forwardSock)
				},
			},
		}

		gomega.Eventually(func(g gomega.Gomega) {
			resp, err := httpClient.Get("http://host/_ping")
			g.Expect(err).ShouldNot(gomega.HaveOccurred())
			g.Expect(resp.StatusCode).To(gomega.Equal(http.StatusOK))
			g.Expect(resp.ContentLength).To(gomega.Equal(int64(2)))

			reply := make([]byte, resp.ContentLength)
			_, err = io.ReadAtLeast(resp.Body, reply, len(reply))

			g.Expect(err).ShouldNot(gomega.HaveOccurred())
			g.Expect(string(reply)).To(gomega.Equal("OK"))
		}).Should(gomega.Succeed())
	})

	ginkgo.It("should reach rootful podman API using unix socket forwarding over ssh", func() {
		httpClient := &http.Client{
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return net.Dial("unix", forwardRootSock)
				},
			},
		}

		gomega.Eventually(func(g gomega.Gomega) {
			resp, err := httpClient.Get("http://host/_ping")
			g.Expect(err).ShouldNot(gomega.HaveOccurred())
			g.Expect(resp.StatusCode).To(gomega.Equal(http.StatusOK))
			g.Expect(resp.ContentLength).To(gomega.Equal(int64(2)))

			reply := make([]byte, resp.ContentLength)
			_, err = io.ReadAtLeast(resp.Body, reply, len(reply))

			g.Expect(err).ShouldNot(gomega.HaveOccurred())
			g.Expect(string(reply)).To(gomega.Equal("OK"))
		}).Should(gomega.Succeed())
	})

	ginkgo.It("should expose and reach an http service using unix to tcp forwarding", func() {
		if runtime.GOOS == "windows" {
			ginkgo.Skip("AF_UNIX not supported on Windows")
		}

		unix2tcpfwdsock, _ := filepath.Abs(filepath.Join(tmpDir, "podman-unix-to-unix-forwarding.sock"))

		out, err := sshExec(`curl http://gateway.containers.internal/services/forwarder/expose -X POST -d'{"protocol":"unix","local":"` + unix2tcpfwdsock + `","remote":"tcp://192.168.127.2:8080"}'`)
		gomega.Expect(string(out)).Should(gomega.Equal(""))
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

		gomega.Eventually(func(g gomega.Gomega) {
			sockfile, err := os.Stat(unix2tcpfwdsock)
			g.Expect(err).ShouldNot(gomega.HaveOccurred())
			g.Expect(sockfile.Mode().Type().String()).To(gomega.Equal(os.ModeSocket.String()))
		}).Should(gomega.Succeed())

		httpClient := &http.Client{
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return net.Dial("unix", unix2tcpfwdsock)
				},
			},
		}

		gomega.Eventually(func(g gomega.Gomega) {
			resp, err := httpClient.Get("http://placeholder/")
			g.Expect(err).ShouldNot(gomega.HaveOccurred())
			g.Expect(resp.StatusCode).To(gomega.Equal(http.StatusOK))
		}).Should(gomega.Succeed())
	})

	ginkgo.It("should expose and reach rootless podman API using unix to unix forwarding over ssh", func() {
		if runtime.GOOS == "windows" {
			ginkgo.Skip("AF_UNIX not supported on Windows")
		}

		unix2unixfwdsock, _ := filepath.Abs(filepath.Join(tmpDir, "podman-unix-to-unix-forwarding.sock"))

		remoteuri := fmt.Sprintf(`ssh-tunnel://root@%s:%d%s?key=%s`, "192.168.127.2", 22, podmanSock, privateKeyFile)
		_, err := sshExec(`curl http://192.168.127.1/services/forwarder/expose -X POST -d'{"protocol":"unix","local":"` + unix2unixfwdsock + `","remote":"` + remoteuri + `"}'`)
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

		gomega.Eventually(func(g gomega.Gomega) {
			sockfile, err := os.Stat(unix2unixfwdsock)
			g.Expect(err).ShouldNot(gomega.HaveOccurred())
			g.Expect(sockfile.Mode().Type().String()).To(gomega.Equal(os.ModeSocket.String()))
		}).Should(gomega.Succeed())

		httpClient := &http.Client{
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return net.Dial("unix", unix2unixfwdsock)
				},
			},
		}

		gomega.Eventually(func(g gomega.Gomega) {
			resp, err := httpClient.Get("http://host/_ping")
			g.Expect(err).ShouldNot(gomega.HaveOccurred())
			g.Expect(resp.StatusCode).To(gomega.Equal(http.StatusOK))
			g.Expect(resp.ContentLength).To(gomega.Equal(int64(2)))

			reply := make([]byte, resp.ContentLength)
			_, err = io.ReadAtLeast(resp.Body, reply, len(reply))

			g.Expect(err).ShouldNot(gomega.HaveOccurred())
			g.Expect(string(reply)).To(gomega.Equal("OK"))
		}).Should(gomega.Succeed())
	})
})
