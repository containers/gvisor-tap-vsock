//go:build !windows

package dns

import "github.com/miekg/dns"

// hostResolvConf lists the host's DNS servers. Windows has no such file.
const hostResolvConf = "/etc/resolv.conf"

// hostNameservers returns a function listing the DNS servers in
// /etc/resolv.conf, which forwarded queries are sent to.
func hostNameservers() func() []string {
	return newResolvConf(hostResolvConf).nameservers
}

// addAnswersFromSystem is only used on Windows, where hostNameservers
// returns nil.
func (h *dnsHandler) addAnswersFromSystem(_ *dns.Msg, _ dns.Question) {}
