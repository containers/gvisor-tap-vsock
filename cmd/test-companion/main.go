package main

import (
	"net"
	"net/http"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

func main() {
	go func() {
		mux := dns.NewServeMux()
		mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			m.RecursionAvailable = true
			for _, q := range m.Question {
				if q.Qtype == dns.TypeA {
					m.Answer = append(m.Answer, &dns.A{
						Hdr: dns.RR_Header{
							Name:   q.Name,
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    0,
						},
						A: net.ParseIP("1.2.3.4"),
					})
				}
			}
			if err := w.WriteMsg(m); err != nil {
				log.Error(err)
			}
		})
		if err := dns.ListenAndServe(":53", "udp", mux); err != nil {
			log.Fatal(err)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte(`Hello world!`))
	})
	log.Fatal(http.ListenAndServe(":8080", mux))
}
