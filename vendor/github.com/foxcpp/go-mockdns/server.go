package mockdns

import (
	"context"
	"errors"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// These constants are re-exported from github.com/miekg/dns for convenience,
// so that users of this package don't need to import github.com/miekg/dns just
// for these.
const (
	RRTypeA     = dns.TypeA
	RRTypeAAAA  = dns.TypeAAAA
	RRTypeCNAME = dns.TypeCNAME
	RRTypeMX    = dns.TypeMX
	RRTypeNS    = dns.TypeNS
	RRTypePTR   = dns.TypePTR
	RRTypeSRV   = dns.TypeSRV
	RRTypeTXT   = dns.TypeTXT
)

// Server is the wrapper that binds Resolver to the DNS server implementation
// from github.com/miekg/dns. This allows it to be used as a replacement
// resolver for testing code that doesn't support DNS callbacks. See PatchNet.
type Server struct {
	mu      sync.RWMutex
	r       Resolver
	stopped bool
	tcpServ dns.Server
	udpServ dns.Server

	Log           Logger
	Authoritative bool
}

type Logger interface {
	Printf(f string, args ...interface{})
}

func NewServer(zones map[string]Zone, authoritative bool) (*Server, error) {
	return NewServerWithLogger(zones, log.New(os.Stderr, "mockdns server: ", log.LstdFlags), authoritative)
}

func NewServerWithLogger(zones map[string]Zone, l Logger, authoritative bool) (*Server, error) {
	if zones == nil {
		zones = make(map[string]Zone)
	}
	s := &Server{
		r: Resolver{
			Zones: zones,
		},
		tcpServ:       dns.Server{Addr: "127.0.0.1:0", Net: "tcp"},
		udpServ:       dns.Server{Addr: "127.0.0.1:0", Net: "udp"},
		Log:           l,
		Authoritative: authoritative,
	}

	tcpL, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}

	// Note we bind TCP on automatic port first since it is more likely to be
	// already used. Then we bind UDP on the same port, hoping it is
	// not taken. We avoid using different ports for TCP and UDP since
	// some applications do not support using a different TCP/UDP ports
	// for DNS.
	pconn, err := net.ListenPacket("udp4", tcpL.Addr().String())
	if err != nil {
		return nil, err
	}

	s.tcpServ.Listener = tcpL
	s.tcpServ.Handler = s
	s.udpServ.PacketConn = pconn
	s.udpServ.Handler = s

	go s.tcpServ.ActivateAndServe()
	go s.udpServ.ActivateAndServe()

	return s, nil
}

func (s *Server) writeErr(w dns.ResponseWriter, reply *dns.Msg, err error) {
	reply.Rcode = dns.RcodeServerFailure
	reply.RecursionAvailable = false
	// A not found response may still include answers (e.g. CNAME chain).
	//reply.Answer = nil
	reply.Extra = nil

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		reply.Rcode = dns.RcodeNameError
		reply.RecursionAvailable = true
		reply.Ns = []dns.RR{
			&dns.SOA{
				Hdr: dns.RR_Header{
					Name:   dnsErr.Name,
					Rrtype: dns.TypeSOA,
					Class:  dns.ClassINET,
					Ttl:    9999,
				},
				Ns:      "localhost.",
				Mbox:    "hostmaster.localhost.",
				Serial:  1,
				Refresh: 900,
				Retry:   900,
				Expire:  1800,
				Minttl:  60,
			},
		}
	} else {
		s.Log.Printf("lookup error: %v", err)
	}

	w.WriteMsg(reply)
}

func mkCname(name, cname string) *dns.CNAME {
	return &dns.CNAME{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeCNAME,
			Class:  dns.ClassINET,
			Ttl:    9999,
		},
		Target: cname,
	}
}

func splitTXT(s string) []string {
	const maxLen = 255

	parts := make([]string, 0, len(s)/maxLen+1)

	min := func(i, j int) int {
		if i < j {
			return i
		}
		return j
	}

	for i := 0; i < len(s)/maxLen+1; i++ {
		p := s[i*maxLen : min(len(s), (i+1)*maxLen)]
		parts = append(parts, p)
	}

	return parts
}

// ServeDNS implements miekg/dns.Handler. It responds with values from underlying
// Resolver object.
func (s *Server) ServeDNS(w dns.ResponseWriter, m *dns.Msg) {
	reply := new(dns.Msg)

	if m.MsgHdr.Opcode != dns.OpcodeQuery {
		reply.SetRcode(m, dns.RcodeRefused)
		if err := w.WriteMsg(reply); err != nil {
			s.Log.Printf("WriteMsg: %v", err)
		}
		return
	}

	reply.SetReply(m)
	reply.RecursionAvailable = true
	if s.Authoritative {
		reply.Authoritative = true
		reply.RecursionAvailable = false
	}

	q := m.Question[0]
	qname := strings.ToLower(dns.Fqdn(q.Name))

	if q.Qclass != dns.ClassINET {
		reply.SetRcode(m, dns.RcodeNotImplemented)
		if err := w.WriteMsg(reply); err != nil {
			s.Log.Printf("WriteMsg: %v", err)
		}
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	switch q.Qtype {
	case dns.TypeA:
		ad, cnames, rname, addrs, err := s.r.lookupA(context.Background(), qname)
		reply.AuthenticatedData = ad
		reply.Answer = appendCNAMEs(reply.Answer, cnames, rname)
		if err != nil {
			s.writeErr(w, reply, err)
			return
		}

		for _, addr := range addrs {
			parsed := net.ParseIP(addr)
			if parsed == nil {
				panic("ServeDNS: malformed IP in records")
			}
			reply.Answer = append(reply.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   rname,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    9999,
				},
				A: parsed,
			})
		}
	case dns.TypeAAAA:
		ad, cnames, rname, addrs, err := s.r.lookupAAAA(context.Background(), q.Name)
		reply.AuthenticatedData = ad
		reply.Answer = appendCNAMEs(reply.Answer, cnames, rname)
		if err != nil {
			s.writeErr(w, reply, err)
			return
		}

		for _, addr := range addrs {
			parsed := net.ParseIP(addr)
			if parsed == nil {
				panic("ServeDNS: malformed IP in records")
			}
			reply.Answer = append(reply.Answer, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   rname,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    9999,
				},
				AAAA: parsed,
			})
		}
	case dns.TypeMX:
		ad, cnames, rname, mxs, err := s.r.lookupMX(context.Background(), q.Name)
		reply.AuthenticatedData = ad
		reply.Answer = appendCNAMEs(reply.Answer, cnames, rname)
		if err != nil {
			s.writeErr(w, reply, err)
			return
		}

		for _, mx := range mxs {
			reply.Answer = append(reply.Answer, &dns.MX{
				Hdr: dns.RR_Header{
					Name:   rname,
					Rrtype: dns.TypeMX,
					Class:  dns.ClassINET,
					Ttl:    9999,
				},
				Preference: mx.Pref,
				Mx:         mx.Host,
			})
		}
	case dns.TypeNS:
		ad, cnames, rname, nss, err := s.r.lookupNS(context.Background(), q.Name)
		reply.AuthenticatedData = ad
		reply.Answer = appendCNAMEs(reply.Answer, cnames, rname)
		if err != nil {
			s.writeErr(w, reply, err)
			return
		}

		for _, ns := range nss {
			reply.Answer = append(reply.Answer, &dns.NS{
				Hdr: dns.RR_Header{
					Name:   rname,
					Rrtype: dns.TypeNS,
					Class:  dns.ClassINET,
					Ttl:    9999,
				},
				Ns: ns.Host,
			})
		}
	case dns.TypeSRV:
		ad, cnames, rname, srvs, err := s.r.lookupSRV(context.Background(), q.Name)
		reply.AuthenticatedData = ad
		reply.Answer = appendCNAMEs(reply.Answer, cnames, rname)
		if err != nil {
			s.writeErr(w, reply, err)
			return
		}

		for _, srv := range srvs {
			reply.Answer = append(reply.Answer, &dns.SRV{
				Hdr: dns.RR_Header{
					Name:   rname,
					Rrtype: dns.TypeSRV,
					Class:  dns.ClassINET,
					Ttl:    9999,
				},
				Priority: srv.Priority,
				Port:     srv.Port,
				Weight:   srv.Weight,
				Target:   srv.Target,
			})
		}
	case dns.TypeCNAME:
		rname := strings.ToLower(dns.Fqdn(q.Name))
		rzone, ok := s.r.Zones[rname]
		if !ok {
			s.writeErr(w, reply, notFound(rname))
			return
		}
		if rzone.CNAME == "" {
			s.writeErr(w, reply, notFound(rname))
			return
		}
		if rzone.Err != nil {
			s.writeErr(w, reply, rzone.Err)
			return
		}
		reply.AuthenticatedData = rzone.AD
		reply.Answer = append(reply.Answer, mkCname(rname, rzone.CNAME))

	case dns.TypeTXT:
		ad, cnames, rname, txts, err := s.r.lookupTXT(context.Background(), q.Name)
		reply.AuthenticatedData = ad
		reply.Answer = appendCNAMEs(reply.Answer, cnames, rname)
		if err != nil {
			s.writeErr(w, reply, err)
			return
		}

		for _, txt := range txts {
			reply.Answer = append(reply.Answer, &dns.TXT{
				Hdr: dns.RR_Header{
					Name:   rname,
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    9999,
				},
				Txt: splitTXT(txt),
			})
		}
	case dns.TypePTR:
		rzone, ok := s.r.Zones[q.Name]
		if !ok {
			s.writeErr(w, reply, notFound(q.Name))
			return
		}
		if rzone.Err != nil {
			s.writeErr(w, reply, rzone.Err)
			return
		}

		reply.AuthenticatedData = rzone.AD
		for _, name := range rzone.PTR {
			reply.Answer = append(reply.Answer, &dns.PTR{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypePTR,
					Class:  dns.ClassINET,
					Ttl:    9999,
				},
				Ptr: name,
			})
		}
	case dns.TypeSOA:
		reply.Answer = []dns.RR{
			&dns.SOA{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeSOA,
					Class:  dns.ClassINET,
					Ttl:    9999,
				},
				Ns:      "localhost.",
				Mbox:    "hostmaster.localhost.",
				Serial:  1,
				Refresh: 900,
				Retry:   900,
				Expire:  1800,
				Minttl:  60,
			},
		}
	default:
		rzone, ok := s.r.Zones[q.Name]
		if !ok {
			s.writeErr(w, reply, notFound(q.Name))
			return
		}
		if rzone.Err != nil {
			s.writeErr(w, reply, rzone.Err)
			return
		}

		reply.AuthenticatedData = rzone.AD
		reply.Answer = append(reply.Answer, rzone.Misc[dns.Type(q.Qtype)]...)
	}

	s.Log.Printf("DNS TRACE %v", reply.String())

	if err := w.WriteMsg(reply); err != nil {
		s.Log.Printf("WriteMsg: %v", err)
	}
}

func appendCNAMEs(answer []dns.RR, cnames []string, rname string) []dns.RR {
	for _, cname := range cnames {
		answer = append(answer, mkCname(rname, cname))
		rname = cname
	}
	return answer
}

// LocalAddr returns the local endpoint used by the server. It will always be
// *net.UDPAddr, however it is also usable for TCP connections.
func (s *Server) LocalAddr() net.Addr {
	return s.udpServ.PacketConn.LocalAddr()
}

// PatchNet configures net.Resolver instance to use this Server object.
//
// Use UnpatchNet to revert changes.
func (s *Server) PatchNet(r *net.Resolver) {
	r.PreferGo = true
	r.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if s.stopped {
			return nil, errors.New("Patched resolver is used after Server.Close")
		}

		dialer := net.Dialer{
			// This is localhost, it is either running or not. Fail quickly if
			// we can't connect.
			Timeout: 1 * time.Second,
		}

		switch network {
		case "udp", "udp4", "udp6":
			return dialer.DialContext(ctx, "udp4", s.udpServ.PacketConn.LocalAddr().String())
		case "tcp", "tcp4", "tcp6":
			return dialer.DialContext(ctx, "tcp4", s.tcpServ.Listener.Addr().String())
		default:
			panic("PatchNet.Dial: unknown network")
		}
	}
}

// NewResolver returns a new net.Resolver instance patched to connect to
// this Server.
func (s *Server) NewResolver() *net.Resolver {
	r := new(net.Resolver)
	s.PatchNet(r)
	return r
}

func UnpatchNet(r *net.Resolver) {
	r.PreferGo = false
	r.Dial = nil
}

// Deprecated: use NewResolver() instead.
func (s *Server) Resolver() *Resolver {
	return &s.r
}

func (s *Server) Close() error {
	s.tcpServ.Shutdown()
	s.udpServ.Shutdown()
	s.stopped = true
	return nil
}

// Reset removes all zones from the server. The function is thread-safe.
func (s *Server) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.r.Zones = make(map[string]Zone)
}

// AppendRR appends a resource record to the zone for the given name. If the
// zone does not exist, it is created. For RR types that only support a single
// value (CNAME), the existing value is replaced. The function is thread-safe.
func (s *Server) AppendRR(name string, rrType uint16, rrData string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !strings.HasSuffix(name, ".") {
		name = name + "."
	}
	zone := s.r.Zones[name]
	switch rrType {
	case dns.TypeA:
		zone.A = append(zone.A, rrData)

	case dns.TypeAAAA:
		zone.AAAA = append(zone.AAAA, rrData)

	case dns.TypeTXT:
		zone.TXT = append(zone.TXT, rrData)

	case dns.TypePTR:
		zone.PTR = append(zone.PTR, rrData)

	case dns.TypeCNAME:
		zone.CNAME = rrData

	case dns.TypeMX:
		parts := strings.SplitN(rrData, " ", 2)
		if len(parts) != 2 {
			return errors.New("invalid MX rrData format")
		}
		pref, err := strconv.Atoi(parts[0])
		if err != nil {
			return errors.New("invalid MX priority")
		}
		mx := net.MX{
			Host: parts[1],
			Pref: uint16(pref),
		}
		zone.MX = append(zone.MX, mx)

	case dns.TypeNS:
		zone.NS = append(zone.NS, net.NS{Host: rrData})

	case dns.TypeSRV:
		parts := strings.SplitN(rrData, " ", 4)
		if len(parts) != 4 {
			return errors.New("invalid SRV rrData format")
		}
		priority, err := strconv.Atoi(parts[0])
		if err != nil {
			return errors.New("invalid SRV priority")
		}
		weight, err := strconv.Atoi(parts[1])
		if err != nil {
			return errors.New("invalid SRV priority")
		}
		port, err := strconv.Atoi(parts[2])
		if err != nil {
			return errors.New("invalid SRV port")
		}
		srv := net.SRV{
			Priority: uint16(priority),
			Weight:   uint16(weight),
			Port:     uint16(port),
			Target:   parts[3],
		}
		zone.SRV = append(zone.SRV, srv)

	default:
		return errors.New("RR type not supported")
	}
	s.r.Zones[name] = zone
	return nil
}

// RemoveRR removes all records of the given type from the zone for the given
// name. If the zone becomes empty, it is removed. The function is thread-safe.
func (s *Server) RemoveRR(name string, rrType uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !strings.HasSuffix(name, ".") {
		name = name + "."
	}
	zone := s.r.Zones[name]
	switch rrType {
	case dns.TypeA:
		zone.A = nil

	case dns.TypeAAAA:
		zone.AAAA = nil

	case dns.TypeTXT:
		zone.TXT = nil

	case dns.TypePTR:
		zone.PTR = nil

	case dns.TypeCNAME:
		zone.CNAME = ""

	case dns.TypeMX:
		zone.MX = nil

	case dns.TypeNS:
		zone.NS = nil

	case dns.TypeSRV:
		zone.SRV = nil

	}
	if isZoneEmpty(zone) {
		delete(s.r.Zones, name)
		return
	}
	s.r.Zones[name] = zone
}

func isZoneEmpty(zone Zone) bool {
	return len(zone.A) == 0 &&
		len(zone.AAAA) == 0 &&
		len(zone.TXT) == 0 &&
		len(zone.PTR) == 0 &&
		zone.CNAME == "" &&
		len(zone.MX) == 0 &&
		len(zone.NS) == 0 &&
		len(zone.SRV) == 0 &&
		len(zone.Misc) == 0
}
