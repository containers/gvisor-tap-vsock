//go:build windows

package dns

import (
	"runtime"
	"testing"
	"unsafe"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// newRecord returns a record laid out like the ones DnsQuery returns, with
// data copied into its Data field. Any pointers in data must be kept alive by
// the caller.
func newRecord[T any](t *testing.T, name string, rrtype uint16, section uint32, data T) *windows.DNSRecord {
	t.Helper()
	r := &windows.DNSRecord{
		Name: utf16(t, name),
		Type: rrtype,
		Dw:   section,
		Ttl:  300,
	}
	require.LessOrEqual(t, unsafe.Sizeof(data), unsafe.Sizeof(r.Data))
	*(*T)(unsafe.Pointer(&r.Data[0])) = data
	return r
}

// newFlatRecord returns a record with wire-format data, the way DnsQuery
// returns record types it does not decode.
func newFlatRecord(t *testing.T, name string, rrtype uint16, rdata ...byte) *windows.DNSRecord {
	t.Helper()
	r := newRecord(t, name, rrtype, windows.DnsSectionAnswer, [0]byte{})
	require.LessOrEqual(t, len(rdata), len(r.Data))
	for _, b := range rdata {
		r.Data[r.Length] = b
		r.Length++
	}
	return r
}

func utf16(t *testing.T, s string) *uint16 {
	t.Helper()
	p, err := windows.UTF16PtrFromString(s)
	require.NoError(t, err)
	t.Cleanup(func() { runtime.KeepAlive(p) })
	return p
}

func TestFromWindowsRecord(t *testing.T) {
	soa := newRecord(t, "example.org", dns.TypeSOA, windows.DnsSectionAnswer, dnsSOAData{
		PrimaryServer: utf16(t, "ns1.example.org"),
		Administrator: utf16(t, "hostmaster.example.org"),
		Serial:        2026110401,
		Refresh:       7200,
		Retry:         3600,
		Expire:        1209600,
		DefaultTTL:    300,
	})
	require.Equal(t, "example.org.\t300\tIN\tSOA\tns1.example.org. hostmaster.example.org. 2026110401 7200 3600 1209600 300",
		fromWindowsRecord(soa).String())

	ptr := newRecord(t, "1.2.0.192.in-addr.arpa", dns.TypePTR, windows.DnsSectionAnswer, windows.DNSPTRData{Host: utf16(t, "host.example.org")})
	require.Equal(t, "1.2.0.192.in-addr.arpa.\t300\tIN\tPTR\thost.example.org.", fromWindowsRecord(ptr).String())

	cname := newRecord(t, "www.example.org", dns.TypeCNAME, windows.DnsSectionAnswer, windows.DNSPTRData{Host: utf16(t, "example.org")})
	require.Equal(t, "www.example.org.\t300\tIN\tCNAME\texample.org.", fromWindowsRecord(cname).String())

	a := newRecord(t, "example.org", dns.TypeA, windows.DnsSectionAnswer, [4]byte{192, 0, 2, 1})
	require.Equal(t, "example.org.\t300\tIN\tA\t192.0.2.1", fromWindowsRecord(a).String())

	aaaa := newRecord(t, "example.org", dns.TypeAAAA, windows.DnsSectionAnswer, [16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 1})
	require.Equal(t, "example.org.\t300\tIN\tAAAA\t2001:db8::1", fromWindowsRecord(aaaa).String())

	mx := newRecord(t, "example.org", dns.TypeMX, windows.DnsSectionAnswer, windows.DNSMXData{NameExchange: utf16(t, "mail.example.org"), Preference: 10})
	require.Equal(t, "example.org.\t300\tIN\tMX\t10 mail.example.org.", fromWindowsRecord(mx).String())

	srv := newRecord(t, "_sip._udp.example.org", dns.TypeSRV, windows.DnsSectionAnswer,
		windows.DNSSRVData{Target: utf16(t, "sip.example.org"), Priority: 1, Weight: 2, Port: 5060})
	require.Equal(t, "_sip._udp.example.org.\t300\tIN\tSRV\t1 2 5060 sip.example.org.", fromWindowsRecord(srv).String())

	// DNS_TXT_DATA ends with a variable-length array of strings.
	txt := newRecord(t, "example.org", dns.TypeTXT, windows.DnsSectionAnswer, struct {
		StringCount uint16
		StringArray [2]*uint16
	}{2, [2]*uint16{utf16(t, "v=spf1 -all"), utf16(t, "second")}})
	require.Equal(t, "example.org.\t300\tIN\tTXT\t\"v=spf1 -all\" \"second\"", fromWindowsRecord(txt).String())

	// CAA is not decoded by DnsQuery: its data is returned in wire format.
	caa := newFlatRecord(t, "example.org", dns.TypeCAA, 0, 5, 'i', 's', 's', 'u', 'e', 'p', 'k', 'i', '.', 'g', 'o', 'o', 'g')
	require.Equal(t, "example.org.\t300\tIN\tCAA\t0 issue \"pki.goog\"", fromWindowsRecord(caa).String())

	// NAPTR is decoded by DnsQuery into a structure that is not converted.
	naptr := newRecord(t, "example.org", dns.TypeNAPTR, windows.DnsSectionAnswer, [40]byte{})
	require.Nil(t, fromWindowsRecord(naptr))

	// Truncated wire-format data.
	badCAA := newFlatRecord(t, "example.org", dns.TypeCAA, 0, 5, 'i')
	require.Nil(t, fromWindowsRecord(badCAA))
}

func TestFromWindowsRecords(t *testing.T) {
	soaData := dnsSOAData{PrimaryServer: utf16(t, "ns1.example.org"), Administrator: utf16(t, "hostmaster.example.org")}
	answer := newRecord(t, "www.example.org", dns.TypeCNAME, windows.DnsSectionAnswer, windows.DNSPTRData{Host: utf16(t, "example.org")})
	local := newRecord(t, "1.2.0.192.in-addr.arpa", dns.TypePTR, windows.DnsSectionQuestion, windows.DNSPTRData{Host: utf16(t, "host")})
	authority := newRecord(t, "example.org", dns.TypeSOA, windows.DnsSectionAuthority, soaData)
	unsupportedAuthority := newRecord(t, "example.org", dns.TypeRRSIG, windows.DnsSectionAuthority, [40]byte{})
	additional := newRecord(t, "ns1.example.org", dns.TypeA, windows.DnsSectionAdditional, [4]byte{192, 0, 2, 53})
	answer.Next = local
	local.Next = authority
	authority.Next = unsupportedAuthority
	unsupportedAuthority.Next = additional

	answers, authorities, ok := fromWindowsRecords(answer)
	require.True(t, ok)
	require.Len(t, answers, 2)
	require.Equal(t, dns.TypeCNAME, answers[0].Header().Rrtype)
	require.Equal(t, dns.TypePTR, answers[1].Header().Rrtype)
	require.Len(t, authorities, 1)
	require.Equal(t, dns.TypeSOA, authorities[0].Header().Rrtype)

	// An answer that cannot be converted fails the whole response rather
	// than giving an incomplete answer.
	unsupportedAnswer := newRecord(t, "example.org", dns.TypeNAPTR, windows.DnsSectionAnswer, [40]byte{})
	unsupportedAnswer.Next = answer
	_, _, ok = fromWindowsRecords(unsupportedAnswer)
	require.False(t, ok)

	answers, authorities, ok = fromWindowsRecords(nil)
	require.True(t, ok)
	require.Empty(t, answers)
	require.Empty(t, authorities)
}

func TestRcodeFromDNSQuery(t *testing.T) {
	for _, tc := range []struct {
		err   error
		rcode int
		ok    bool
	}{
		{nil, dns.RcodeSuccess, true},
		{windows.DNS_INFO_NO_RECORDS, dns.RcodeSuccess, true},
		{windows.DNS_ERROR_RCODE_NAME_ERROR, dns.RcodeNameError, true},
		{windows.DNS_ERROR_RCODE_SERVER_FAILURE, dns.RcodeServerFailure, true},
		{windows.DNS_ERROR_RCODE_REFUSED, dns.RcodeRefused, true},
		{windows.DNS_ERROR_RCODE_NOTZONE, dns.RcodeNotZone, true},
		// Not a response code that fits in the DNS header.
		{windows.DNS_ERROR_RCODE_BADSIG, 0, false},
		{windows.ERROR_TIMEOUT, 0, false},
		{windows.DNS_ERROR_NO_DNS_SERVERS, 0, false},
	} {
		rcode, ok := rcodeFromDNSQuery(tc.err)
		require.Equal(t, tc.ok, ok, "%v", tc.err)
		require.Equal(t, tc.rcode, rcode, "%v", tc.err)
	}
}

// TestAddAnswersFromSystem sends real queries through the Windows DNS client.
func TestAddAnswersFromSystem(t *testing.T) {
	server, err := New(nil, nil, nil)
	require.NoError(t, err)
	require.Nil(t, server.handler.nameservers)

	query := func(name string, qtype uint16) *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion(name, qtype)
		server.handler.addAnswers(m)
		return m
	}

	soa := query("redhat.com.", dns.TypeSOA)
	require.Equal(t, dns.RcodeSuccess, soa.Rcode)
	require.NotEmpty(t, soa.Answer)
	require.IsType(t, &dns.SOA{}, soa.Answer[0])
	require.Equal(t, "redhat.com.", soa.Answer[0].Header().Name)

	ptr := query("8.8.8.8.in-addr.arpa.", dns.TypePTR)
	require.Equal(t, dns.RcodeSuccess, ptr.Rcode)
	require.NotEmpty(t, ptr.Answer)
	require.Equal(t, "dns.google.", ptr.Answer[0].(*dns.PTR).Ptr)

	caa := query("google.com.", dns.TypeCAA)
	require.Equal(t, dns.RcodeSuccess, caa.Rcode)
	if len(caa.Answer) == 0 {
		// Older versions of Windows (Server 2022, build 20348) leave out
		// the record types they do not parse.
		t.Log("DnsQuery returned no CAA records")
	} else {
		require.Contains(t, caa.Answer[0].String(), "pki.goog")
	}

	// Windows Server 2025 answers a repeated query for a missing name from
	// its cache with ERROR_TIMEOUT.
	for range 3 {
		nx := query("does-not-exist.gvisor-tap-vsock.google.com.", dns.TypeSOA)
		require.Equal(t, dns.RcodeNameError, nx.Rcode)
		require.Empty(t, nx.Answer)
	}
}
