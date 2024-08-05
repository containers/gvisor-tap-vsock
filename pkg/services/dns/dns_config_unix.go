//go:build !windows

package dns

import (
	"fmt"
	"os"

	"github.com/miekg/dns"
)

func GetDNSHostAndPort() (string, string, error) {
	conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return "", "", err
	}
	// TODO: use all configured nameservers, instead just first one
	nameserver := conf.Servers[0]

	return nameserver, conf.Port, nil
}
