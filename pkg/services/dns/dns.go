package dns

import (
	"context"
	"net"
	"strings"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

type dnsHandler struct {
	static map[string]net.IP
}

func (h *dnsHandler) handle(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.RecursionAvailable = true
	h.addAnswers(m)
	if err := w.WriteMsg(m); err != nil {
		log.Error(err)
	}
}

func (h *dnsHandler) addAnswers(m *dns.Msg) {
	for _, q := range m.Question {
		log.Debugf("DNS query for %s", q.String())
		resolver := net.Resolver{
			PreferGo: false,
		}
		switch q.Qtype {
		case dns.TypeNS:
			records, err := resolver.LookupNS(context.TODO(), q.Name)
			if err != nil {
				m.Rcode = dns.RcodeNameError
				return
			}
			for _, ns := range records {
				m.Answer = append(m.Answer, &dns.NS{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeNS,
						Class:  dns.ClassINET,
						Ttl:    0,
					},
					Ns: ns.Host,
				})
			}
		case dns.TypeA:
			for name, ip := range h.static {
				if strings.HasSuffix(q.Name, name) {
					m.Answer = append(m.Answer, &dns.A{
						Hdr: dns.RR_Header{
							Name:   q.Name,
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    0,
						},
						A: ip,
					})
					return
				}
			}
			ips, err := resolver.LookupIPAddr(context.TODO(), q.Name)
			if err != nil {
				m.Rcode = dns.RcodeNameError
				return
			}
			for _, ip := range ips {
				if len(ip.IP.To4()) != net.IPv4len {
					continue
				}
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    0,
					},
					A: ip.IP.To4(),
				})
			}
		}
	}
}

func Serve(udpConn net.PacketConn, static map[string]net.IP) error {
	mux := dns.NewServeMux()
	handler := &dnsHandler{static: static}
	mux.HandleFunc(".", handler.handle)
	srv := &dns.Server{
		PacketConn: udpConn,
		Handler:    mux,
	}
	return srv.ActivateAndServe()
}
