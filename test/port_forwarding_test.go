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
		_, err := net.Dial("tcp", "127.0.0.1:9090")
		Expect(err).Should(HaveOccurred())
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
			g.Expect(err).Should(HaveOccurred())
			g.Expect(err.Error()).To(HaveSuffix("connection refused"))
		}).Should(Succeed())
	})

	It("should reach a dns server in the VM using dynamic port forwarding", func() {
		Expect(client.Expose(&types.ExposeRequest{
			Local:    ":1053",
			Remote:   "192.168.127.2:53",
			Protocol: "udp",
		})).Should(Succeed())

		Eventually(func(g Gomega) {
			cmd := exec.Command("nslookup", "-timeout=1", "-port=1053", "foobar", "127.0.0.1")
			out, err := cmd.CombinedOutput()
			g.Expect(err).ShouldNot(HaveOccurred())
			g.Expect(string(out)).To(ContainSubstring("Address: 1.2.3.4"))
		}).Should(Succeed())

		Expect(client.Unexpose(&types.UnexposeRequest{
			Local:    ":1053",
			Protocol: "udp",
		})).Should(Succeed())
	})

	It("should reach a http server in the VM using the tunneling of the daemon", func() {
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

	It("should reach a http server in the VM using dynamic port forwarding configured within the VM", func() {
		_, err := net.Dial("tcp", "127.0.0.1:9090")
		Expect(err).Should(HaveOccurred())
		Expect(err.Error()).To(HaveSuffix("connection refused"))

		_, err = sshExec(`curl http://gateway.containers.internal/services/forwarder/expose -X POST -d'{"local":":9090", "remote":":8080"}'`)
		Expect(err).ShouldNot(HaveOccurred())

		Eventually(func(g Gomega) {
			resp, err := http.Get("http://127.0.0.1:9090")
			g.Expect(err).ShouldNot(HaveOccurred())
			g.Expect(resp.StatusCode).To(Equal(http.StatusOK))
		}).Should(Succeed())

		_, err = sshExec(`curl http://gateway.containers.internal/services/forwarder/unexpose -X POST -d'{"local":":9090"}'`)
		Expect(err).ShouldNot(HaveOccurred())

		Eventually(func(g Gomega) {
			_, err = net.Dial("tcp", "127.0.0.1:9090")
			g.Expect(err).Should(HaveOccurred())
			g.Expect(err.Error()).To(HaveSuffix("connection refused"))
		}).Should(Succeed())
	})

	It("should reach rootless podman API using unix socket forwarding over ssh", func() {
		httpClient := &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return net.Dial("unix", forwardSock)
				},
			},
		}

		Eventually(func(g Gomega) {
			resp, err := httpClient.Get("http://host/_ping")
			g.Expect(err).ShouldNot(HaveOccurred())
			g.Expect(resp.StatusCode).To(Equal(http.StatusOK))
			g.Expect(resp.ContentLength).To(Equal(int64(2)))

			reply := make([]byte, resp.ContentLength)
			_, err = io.ReadAtLeast(resp.Body, reply, len(reply))

			g.Expect(err).ShouldNot(HaveOccurred())
			g.Expect(string(reply)).To(Equal("OK"))
		}).Should(Succeed())
	})

	It("should reach rootful podman API using unix socket forwarding over ssh", func() {
		httpClient := &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return net.Dial("unix", forwardRootSock)
				},
			},
		}

		Eventually(func(g Gomega) {
			resp, err := httpClient.Get("http://host/_ping")
			g.Expect(err).ShouldNot(HaveOccurred())
			g.Expect(resp.StatusCode).To(Equal(http.StatusOK))
			g.Expect(resp.ContentLength).To(Equal(int64(2)))

			reply := make([]byte, resp.ContentLength)
			_, err = io.ReadAtLeast(resp.Body, reply, len(reply))

			g.Expect(err).ShouldNot(HaveOccurred())
			g.Expect(string(reply)).To(Equal("OK"))
		}).Should(Succeed())
	})

	It("should expose and reach an http service using unix to tcp forwarding", func() {
		if runtime.GOOS == "windows" {
			Skip("AF_UNIX not supported on Windows")
		}

		unix2tcpfwdsock, _ := filepath.Abs(filepath.Join(tmpDir, "podman-unix-to-unix-forwarding.sock"))

		out, err := sshExec(`curl http://gateway.containers.internal/services/forwarder/expose -X POST -d'{"protocol":"unix","local":"` + unix2tcpfwdsock + `","remote":"tcp://192.168.127.2:8080"}'`)
		Expect(string(out)).Should(Equal(""))
		Expect(err).ShouldNot(HaveOccurred())

		Eventually(func(g Gomega) {
			sockfile, err := os.Stat(unix2tcpfwdsock)
			g.Expect(err).ShouldNot(HaveOccurred())
			g.Expect(sockfile.Mode().Type().String()).To(Equal(os.ModeSocket.String()))
		}).Should(Succeed())

		httpClient := &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return net.Dial("unix", unix2tcpfwdsock)
				},
			},
		}

		Eventually(func(g Gomega) {
			resp, err := httpClient.Get("http://placeholder/")
			g.Expect(err).ShouldNot(HaveOccurred())
			g.Expect(resp.StatusCode).To(Equal(http.StatusOK))
		}).Should(Succeed())
	})

	It("should expose and reach rootless podman API using unix to unix forwarding over ssh", func() {
		if runtime.GOOS == "windows" {
			Skip("AF_UNIX not supported on Windows")
		}

		unix2unixfwdsock, _ := filepath.Abs(filepath.Join(tmpDir, "podman-unix-to-unix-forwarding.sock"))

		remoteuri := fmt.Sprintf(`ssh-tunnel://%s:%d%s?user=root&key=%s`, "192.168.127.2", 22, podmanSock, privateKeyFile)
		_, err := sshExec(`curl http://192.168.127.1/services/forwarder/expose -X POST -d'{"protocol":"unix","local":"` + unix2unixfwdsock + `","remote":"` + remoteuri + `"}'`)
		Expect(err).ShouldNot(HaveOccurred())

		Eventually(func(g Gomega) {
			sockfile, err := os.Stat(unix2unixfwdsock)
			g.Expect(err).ShouldNot(HaveOccurred())
			g.Expect(sockfile.Mode().Type().String()).To(Equal(os.ModeSocket.String()))
		}).Should(Succeed())

		httpClient := &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return net.Dial("unix", unix2unixfwdsock)
				},
			},
		}

		Eventually(func(g Gomega) {
			resp, err := httpClient.Get("http://host/_ping")
			g.Expect(err).ShouldNot(HaveOccurred())
			g.Expect(resp.StatusCode).To(Equal(http.StatusOK))
			g.Expect(resp.ContentLength).To(Equal(int64(2)))

			reply := make([]byte, resp.ContentLength)
			_, err = io.ReadAtLeast(resp.Body, reply, len(reply))

			g.Expect(err).ShouldNot(HaveOccurred())
			g.Expect(string(reply)).To(Equal("OK"))
		}).Should(Succeed())
	})
})
