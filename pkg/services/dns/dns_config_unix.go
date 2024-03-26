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
	nameserver := conf.Servers[0]

	// if the nameserver is from /etc/resolv.conf the [ and ] are already
	// added, thereby breaking net.ParseIP. Check for this and don't
	// fully qualify such a name
	if nameserver[0] == '[' && nameserver[len(nameserver)-1] == ']' {
		nameserver = nameserver[1 : len(nameserver)-1]
	}

	return nameserver, conf.Port, nil
}
