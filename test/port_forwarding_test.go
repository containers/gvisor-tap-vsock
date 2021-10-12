package e2e

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"os/exec"

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

	It("should reach a dns server in the VM using dynamic port forwarding", func() {
		const dnsmasqConfiguration = `user=root
port=53
bind-interfaces
address=/foobar/1.2.3.4
`
		base64Data := base64.StdEncoding.EncodeToString([]byte(dnsmasqConfiguration))
		_, err := sshExec(fmt.Sprintf("sudo install -m 0%o /dev/null %s && cat <<EOF | base64 --decode | sudo tee %s\n%s\nEOF", 0644, "/tmp/cfg", "/tmp/cfg", base64Data))
		Expect(err).ShouldNot(HaveOccurred())

		_, _ = sshExec("sudo podman pull quay.io/crcont/dnsmasq")

		_, err = sshExec("sudo podman run --rm --name dns-test -v /tmp/cfg:/etc/dnsmasq.conf:z -d -p 53:53/udp -t quay.io/crcont/dnsmasq")
		Expect(err).ShouldNot(HaveOccurred())
		defer func() {
			_, err := sshExec("sudo podman stop dns-test")
			Expect(err).ShouldNot(HaveOccurred())
		}()

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

	It("should reach a http server in the VM using dynamic port forwarding configured within the VM", func() {
		_, err := sshExec("sudo podman run --rm --name http-test -d -p 8080:80 -t docker.io/library/nginx:alpine")
		Expect(err).ShouldNot(HaveOccurred())
		defer func() {
			_, err := sshExec("sudo podman stop http-test")
			Expect(err).ShouldNot(HaveOccurred())
		}()

		_, err = net.Dial("tcp", "127.0.0.1:9090")
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
			g.Expect(err.Error()).To(HaveSuffix("connection refused"))
		}).Should(Succeed())
	})
})
