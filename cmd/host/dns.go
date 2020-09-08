package main

import (
	"context"
	"net"

	log "github.com/golang/glog"
	"github.com/miekg/dns"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.RecursionAvailable = true

	for _, q := range m.Question {
		log.Infof("DNS query for %s", q.String())
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
		case dns.TypeAAAA:
			ips, err := resolver.LookupIPAddr(context.TODO(), q.Name)
			if err != nil {
				m.Rcode = dns.RcodeNameError
				return
			}
			for _, ip := range ips {
				if len(ip.IP) != net.IPv6len {
					continue
				}
				m.Answer = append(m.Answer, &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    0,
					},
					AAAA: ip.IP.To16(),
				})
			}
		case dns.TypeA:
			ips, err := resolver.LookupIPAddr(context.TODO(), q.Name)
			if err != nil {
				m.Rcode = dns.RcodeNameError
				return
			}
			for _, ip := range ips {
				if len(ip.IP) != net.IPv4len {
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

	if err := w.WriteMsg(m); err != nil {
		log.Error(err)
	}
}

func dnsServer(s *stack.Stack) error {
	udpConn, err := gonet.DialUDP(s, &tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.Address(net.ParseIP(gateway).To4()),
		Port: uint16(53),
	}, nil, ipv4.ProtocolNumber)
	if err != nil {
		return err
	}

	mux := dns.NewServeMux()
	mux.HandleFunc(".", handleDNSRequest)
	srv := &dns.Server{
		PacketConn: udpConn,
		Handler:    mux,
	}
	return srv.ActivateAndServe()
}
