package dns

import (
	"net"
	"testing"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/miekg/dns"
)

func TestEgressPolicyBlocksExternalDNSFallback(t *testing.T) {
	h := &dnsHandler{allowUpstream: false}
	m := new(dns.Msg)
	m.SetQuestion("example.invalid.", dns.TypeA)
	h.addAnswers(m)
	if m.Rcode != dns.RcodeRefused {
		t.Fatalf("got Rcode %d, want REFUSED", m.Rcode)
	}
	if len(m.Answer) != 0 {
		t.Fatalf("got unexpected external answer: %v", m.Answer)
	}
}

func TestEgressPolicyKeepsLocalDNSZones(t *testing.T) {
	h := &dnsHandler{
		allowUpstream: false,
		zones: []types.Zone{{
			Name:      "internal.",
			DefaultIP: net.ParseIP("192.168.127.1"),
		}},
	}
	m := new(dns.Msg)
	m.SetQuestion("host.internal.", dns.TypeA)
	h.addAnswers(m)
	if m.Rcode != dns.RcodeSuccess || len(m.Answer) != 1 {
		t.Fatalf("got rcode=%d answers=%v, want local A answer", m.Rcode, m.Answer)
	}
}
