//go:build windows

package dns

import (
	"errors"
	"net"
	"slices"
	"syscall"
	"unsafe"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

// hostNameservers returns nil: Windows has no /etc/resolv.conf, so queries
// for record types that Go's net.Resolver cannot look up are answered by
// addAnswersFromSystem instead.
func hostNameservers() func() []string {
	return nil
}

const (
	// dnsSectionMask selects the section bits of DNSRecord.Dw.
	dnsSectionMask = 0x3
	// dnsFreeRecordList is the free type DnsRecordListFree expects for the
	// records returned by DnsQuery.
	dnsFreeRecordList = 1
	// dnsQueryBypassCache is DNS_QUERY_BYPASS_CACHE.
	dnsQueryBypassCache = 0x8
)

// dnsSOAData is DNS_SOA_DATA from windns.h.
type dnsSOAData struct {
	PrimaryServer *uint16
	Administrator *uint16
	Serial        uint32
	Refresh       uint32
	Retry         uint32
	Expire        uint32
	DefaultTTL    uint32
}

// parsedTypes are the record types that DnsQuery returns decoded into a
// type-specific structure. Records of any other type are returned "flat",
// with their data in wire format. See DNS_QUERY_PARSE_ALL_RECORDS in
// https://learn.microsoft.com/en-us/windows/win32/dns/dns-constants
var parsedTypes = []uint16{
	dns.TypeA, dns.TypeNS, dns.TypeMD, dns.TypeMF, dns.TypeCNAME, dns.TypeSOA,
	dns.TypeMB, dns.TypeMG, dns.TypeMR, windows.DNS_TYPE_WKS, dns.TypePTR, dns.TypeHINFO,
	dns.TypeMINFO, dns.TypeMX, dns.TypeTXT, dns.TypeRP, dns.TypeAFSDB, dns.TypeX25,
	dns.TypeISDN, dns.TypeRT, dns.TypeSIG, dns.TypeKEY, dns.TypeAAAA, dns.TypeSRV,
	dns.TypeATMA, dns.TypeNAPTR, dns.TypeDNAME, dns.TypeOPT, dns.TypeDS,
	dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY, dns.TypeDHCID, dns.TypeNSEC3,
	dns.TypeNSEC3PARAM, dns.TypeTLSA, dns.TypeTKEY, dns.TypeTSIG,
	windows.DNS_TYPE_WINS, windows.DNS_TYPE_WINSR,
}

// addAnswersFromSystem answers q with the Windows DNS client (DnsQuery). It
// follows the host's DNS settings as they change, such as the DNS servers of
// each network adapter and the name resolution policies set by VPNs.
func (h *dnsHandler) addAnswersFromSystem(m *dns.Msg, q dns.Question) {
	records, err := dnsQuery(q)
	if records != nil {
		defer windows.DnsRecordListFree(records, dnsFreeRecordList)
	}

	rcode, ok := rcodeFromDNSQuery(err)
	if !ok {
		log.Debugf("DnsQuery for %s %s failed: %v", q.Name, dns.TypeToString[q.Qtype], err)
		m.Rcode = dns.RcodeServerFailure
		return
	}

	answer, authority, ok := fromWindowsRecords(records)
	if !ok {
		log.Debugf("DnsQuery for %s %s returned records that cannot be converted", q.Name, dns.TypeToString[q.Qtype])
		m.Rcode = dns.RcodeServerFailure
		return
	}
	m.Answer = append(m.Answer, answer...)
	m.Ns = append(m.Ns, authority...)
	m.Rcode = rcode
}

// dnsQuery sends q through the Windows DNS client. The returned records must
// be freed with DnsRecordListFree.
func dnsQuery(q dns.Question) (*windows.DNSRecord, error) {
	var records *windows.DNSRecord
	err := windows.DnsQuery(q.Name, q.Qtype, 0, nil, &records, nil)
	if errors.Is(err, windows.ERROR_TIMEOUT) {
		// For a few seconds after finding that a name does not exist,
		// Windows Server 2025 answers queries for it from its cache with
		// ERROR_TIMEOUT. Ask the DNS servers again to get the real answer.
		if records != nil {
			windows.DnsRecordListFree(records, dnsFreeRecordList)
			records = nil
		}
		err = windows.DnsQuery(q.Name, q.Qtype, dnsQueryBypassCache, nil, &records, nil)
	}
	return records, err
}

// rcodeFromDNSQuery returns the response code matching the result of
// DnsQuery, or false if no DNS server answered.
func rcodeFromDNSQuery(err error) (int, bool) {
	var errno syscall.Errno
	switch {
	case err == nil, errors.Is(err, windows.DNS_INFO_NO_RECORDS):
		return dns.RcodeSuccess, true
	case errors.As(err, &errno) && errno > windows.DNS_ERROR_RESPONSE_CODES_BASE && errno <= windows.DNS_ERROR_RCODE_NOTZONE:
		// The server answered with an error code, such as NXDOMAIN.
		return int(errno - windows.DNS_ERROR_RESPONSE_CODES_BASE), true
	default:
		return 0, false
	}
}

// fromWindowsRecords converts the answer and authority records returned by
// DnsQuery. It returns false if an answer record cannot be converted, as
// leaving it out would give the guest an incomplete answer. Authority records
// that cannot be converted are left out.
func fromWindowsRecords(records *windows.DNSRecord) (answer, authority []dns.RR, ok bool) {
	for r := records; r != nil; r = r.Next {
		section := r.Dw & dnsSectionMask
		// Records answered locally (hosts file, local names) come back in
		// the question section.
		isAnswer := section == windows.DnsSectionAnswer || section == windows.DnsSectionQuestion
		if !isAnswer && section != windows.DnsSectionAuthority {
			continue
		}
		rr := fromWindowsRecord(r)
		switch {
		case rr == nil && isAnswer:
			return nil, nil, false
		case rr == nil:
			continue
		case isAnswer:
			answer = append(answer, rr)
		default:
			authority = append(authority, rr)
		}
	}
	return answer, authority, true
}

// fromWindowsRecord converts one record returned by DnsQuery, or returns nil
// if its type is not supported.
func fromWindowsRecord(r *windows.DNSRecord) dns.RR {
	hdr := dns.RR_Header{
		Name:   dns.Fqdn(windows.UTF16PtrToString(r.Name)),
		Rrtype: r.Type,
		Class:  dns.ClassINET,
		Ttl:    r.Ttl,
	}
	data := unsafe.Pointer(&r.Data[0])
	switch r.Type {
	case dns.TypeA:
		return &dns.A{Hdr: hdr, A: net.IP(slices.Clone((*[net.IPv4len]byte)(data)[:]))}
	case dns.TypeAAAA:
		return &dns.AAAA{Hdr: hdr, AAAA: net.IP(slices.Clone((*[net.IPv6len]byte)(data)[:]))}
	case dns.TypeCNAME:
		return &dns.CNAME{Hdr: hdr, Target: hostName(data)}
	case dns.TypeDNAME:
		return &dns.DNAME{Hdr: hdr, Target: hostName(data)}
	case dns.TypeNS:
		return &dns.NS{Hdr: hdr, Ns: hostName(data)}
	case dns.TypePTR:
		return &dns.PTR{Hdr: hdr, Ptr: hostName(data)}
	case dns.TypeMX:
		mx := (*windows.DNSMXData)(data)
		return &dns.MX{Hdr: hdr, Mx: dns.Fqdn(windows.UTF16PtrToString(mx.NameExchange)), Preference: mx.Preference}
	case dns.TypeSRV:
		srv := (*windows.DNSSRVData)(data)
		return &dns.SRV{
			Hdr:      hdr,
			Target:   dns.Fqdn(windows.UTF16PtrToString(srv.Target)),
			Priority: srv.Priority,
			Weight:   srv.Weight,
			Port:     srv.Port,
		}
	case dns.TypeTXT:
		txt := (*windows.DNSTXTData)(data)
		strs := unsafe.Slice(&txt.StringArray[0], txt.StringCount)
		rr := &dns.TXT{Hdr: hdr, Txt: make([]string, 0, len(strs))}
		for _, s := range strs {
			rr.Txt = append(rr.Txt, windows.UTF16PtrToString(s))
		}
		return rr
	case dns.TypeSOA:
		soa := (*dnsSOAData)(data)
		return &dns.SOA{
			Hdr:     hdr,
			Ns:      dns.Fqdn(windows.UTF16PtrToString(soa.PrimaryServer)),
			Mbox:    dns.Fqdn(windows.UTF16PtrToString(soa.Administrator)),
			Serial:  soa.Serial,
			Refresh: soa.Refresh,
			Retry:   soa.Retry,
			Expire:  soa.Expire,
			Minttl:  soa.DefaultTTL,
		}
	}
	if slices.Contains(parsedTypes, r.Type) {
		return nil
	}
	// A flat record (CAA, HTTPS, ...): its data is in wire format.
	hdr.Rdlength = r.Length
	rr, _, err := dns.UnpackRRWithHeader(hdr, unsafe.Slice((*byte)(data), r.Length), 0)
	if err != nil {
		return nil
	}
	return rr
}

// hostName returns the name in a DNS_PTR_DATA structure, the format used for
// CNAME, DNAME, NS and PTR records.
func hostName(data unsafe.Pointer) string {
	return dns.Fqdn(windows.UTF16PtrToString((*windows.DNSPTRData)(data).Host))
}
