//go:build !windows

package dns

import (
	"net"
	"net/netip"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

func getDNSHostAndPort() ([]string, error) {
	conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return []string{}, err
	}
	var hosts = make([]string, len(conf.Servers))
	for _, server := range conf.Servers {
		dnsIP, err := netip.ParseAddr(server)
		if err != nil {
			log.Errorf("Failed to parse DNS IP address: %s", server)
			continue
		}
		// add only ipv4 dns addresses
		if dnsIP.Is4() {
			hosts = append(hosts, net.JoinHostPort(server, conf.Port))
		}
	}

	return hosts, nil
}
