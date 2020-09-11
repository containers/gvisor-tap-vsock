package e2e

import (
	"context"
	"io/ioutil"
	"net"
	"net/http"
	"os/exec"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("connectivity", func() {
	It("should ping the tap device", func() {
		_, _, err := Exec(exec.Command("ping", "-c4", "192.168.127.2"), nil)
		Expect(err).ShouldNot(HaveOccurred())
	})

	It("should ping the gateway", func() {
		_, _, err := Exec(exec.Command("ping", "-c4", "192.168.127.1"), nil)
		Expect(err).ShouldNot(HaveOccurred())
	})

	It("should ping 8.8.8.8", func() {
		_, _, err := Exec(exec.Command("sudo", "route", "add", "-net", "8.8.8.8", "netmask", "255.255.255.255", "gw", "192.168.127.1"), nil)
		Expect(err).ShouldNot(HaveOccurred())
		defer func() {
			_, _, err := Exec(exec.Command("sudo", "route", "del", "-net", "8.8.8.8", "netmask", "255.255.255.255", "gw", "192.168.127.1"), nil)
			Expect(err).ShouldNot(HaveOccurred())
		}()
		_, _, err = Exec(exec.Command("ping", "-c4", "8.8.8.8"), nil)
		Expect(err).ShouldNot(HaveOccurred())
	})
})

var _ = Describe("dns", func() {
	It("should resolve redhat.com", func() {
		resolver := net.Resolver{
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return net.Dial("udp", "192.168.127.1:53")
			},
		}
		names, err := resolver.LookupIPAddr(context.Background(), "redhat.com")
		Expect(err).ShouldNot(HaveOccurred())
		Expect(names).To(HaveLen(1))
		Expect(names[0].String()).To(Equal("209.132.183.105"))
	})
})

var _ = Describe("http", func() {
	It("should connect to the internal http server", func() {
		res, err := http.Get("http://192.168.127.1")
		Expect(err).ShouldNot(HaveOccurred())
		bin, err := ioutil.ReadAll(res.Body)
		defer res.Body.Close()
		Expect(err).ShouldNot(HaveOccurred())
		Expect(string(bin)).To(Equal("Hello world"))
	})
})
