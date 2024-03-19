package dns

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

type dnsHandler struct {
	zones      []types.Zone
	zonesLock  sync.RWMutex
	dnsClient  *dns.Client
	nameserver string
}

func newDnsHandler(zones []types.Zone) *dnsHandler {

	dnsClient, nameserver := readAndCreateClient()

	return &dnsHandler{
		zones:      zones,
		dnsClient:  dnsClient,
		nameserver: nameserver,
	}

}

func readAndCreateClient() (*dns.Client, string) {
	conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	nameserver := conf.Servers[0]

	// if the nameserver is from /etc/resolv.conf the [ and ] are already
	// added, thereby breaking net.ParseIP. Check for this and don't
	// fully qualify such a name
	if nameserver[0] == '[' && nameserver[len(nameserver)-1] == ']' {
		nameserver = nameserver[1 : len(nameserver)-1]
	}
	if i := net.ParseIP(nameserver); i != nil {
		nameserver = net.JoinHostPort(nameserver, conf.Port)
	} else {
		nameserver = dns.Fqdn(nameserver) + ":" + conf.Port
	}
	client := new(dns.Client)
	client.Net = "udp"

	client.DialTimeout = 2 * time.Second
	client.ReadTimeout = 2 * time.Second
	client.WriteTimeout = 2 * time.Second

	return client, nameserver
}

func (h *dnsHandler) handle(w dns.ResponseWriter, r *dns.Msg, responseMessageSize int) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.RecursionAvailable = true
	h.addAnswers(m)
	edns0 := r.IsEdns0()
	if edns0 != nil {
		responseMessageSize = int(edns0.UDPSize())
	}
	m.Truncate(responseMessageSize)
	if err := w.WriteMsg(m); err != nil {
		log.Error(err)
	}
}

func (h *dnsHandler) handleTCP(w dns.ResponseWriter, r *dns.Msg) {
	h.handle(w, r, dns.MaxMsgSize)
}

func (h *dnsHandler) handleUDP(w dns.ResponseWriter, r *dns.Msg) {
	h.handle(w, r, dns.MinMsgSize)
}

func (h *dnsHandler) addAnswers(m *dns.Msg) {
	h.zonesLock.RLock()
	defer h.zonesLock.RUnlock()
	for _, q := range m.Question {
		for _, zone := range h.zones {
			zoneSuffix := fmt.Sprintf(".%s", zone.Name)
			if strings.HasSuffix(q.Name, zoneSuffix) {
				if q.Qtype != dns.TypeA {
					return
				}
				for _, record := range zone.Records {
					withoutZone := strings.TrimSuffix(q.Name, zoneSuffix)
					if (record.Name != "" && record.Name == withoutZone) ||
						(record.Regexp != nil && record.Regexp.MatchString(withoutZone)) {
						m.Answer = append(m.Answer, &dns.A{
							Hdr: dns.RR_Header{
								Name:   q.Name,
								Rrtype: dns.TypeA,
								Class:  dns.ClassINET,
								Ttl:    0,
							},
							A: record.IP,
						})
						return
					}
				}
				if !zone.DefaultIP.Equal(net.IP("")) {
					m.Answer = append(m.Answer, &dns.A{
						Hdr: dns.RR_Header{
							Name:   q.Name,
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    0,
						},
						A: zone.DefaultIP,
					})
					return
				}
				m.Rcode = dns.RcodeNameError
				return
			}
		}

		// need to create new message struct, as reusing original message struct leading
		// to request errors
		message := &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Authoritative:     m.Authoritative,
				AuthenticatedData: m.AuthenticatedData,
				CheckingDisabled:  m.CheckingDisabled,
				RecursionDesired:  m.RecursionDesired,
				Opcode:            m.Opcode,
			},
			Question: make([]dns.Question, 1),
		}
		message.Question[0] = q
		message.Id = dns.Id()

		r, _, err := h.dnsClient.Exchange(message, h.nameserver)

		if err != nil {
			m.Rcode = dns.RcodeNameError
			fmt.Fprintf(os.Stderr, "Error: %v \n", err)
			return
		}

		m.Answer = append(m.Answer, r.Answer...)
	}
}

type Server struct {
	udpConn net.PacketConn
	tcpLn   net.Listener
	handler *dnsHandler
}

func New(udpConn net.PacketConn, tcpLn net.Listener, zones []types.Zone) (*Server, error) {
	handler := newDnsHandler(zones)
	return &Server{udpConn: udpConn, tcpLn: tcpLn, handler: handler}, nil
}

func (s *Server) Serve() error {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handler.handleUDP)
	srv := &dns.Server{
		PacketConn: s.udpConn,
		Handler:    mux,
	}
	return srv.ActivateAndServe()
}

func (s *Server) ServeTCP() error {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handler.handleTCP)
	tcpSrv := &dns.Server{
		Listener: s.tcpLn,
		Handler:  mux,
	}
	return tcpSrv.ActivateAndServe()
}

func (s *Server) Mux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/all", func(w http.ResponseWriter, _ *http.Request) {
		s.handler.zonesLock.RLock()
		_ = json.NewEncoder(w).Encode(s.handler.zones)
		s.handler.zonesLock.RUnlock()
	})

	mux.HandleFunc("/add", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "post only", http.StatusBadRequest)
			return
		}
		var req types.Zone
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		s.addZone(req)
		w.WriteHeader(http.StatusOK)
	})
	return mux
}

func (s *Server) addZone(req types.Zone) {
	s.handler.zonesLock.Lock()
	defer s.handler.zonesLock.Unlock()
	for i, zone := range s.handler.zones {
		if zone.Name == req.Name {
			req.Records = append(req.Records, zone.Records...)
			s.handler.zones[i] = req
			return
		}
	}
	// No existing zone for req.Name, add new one
	s.handler.zones = append(s.handler.zones, req)
}
