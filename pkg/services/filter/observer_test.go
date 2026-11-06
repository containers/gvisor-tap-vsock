package filter

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRecordConnection_StatusUpdatesOnChange(t *testing.T) {
	obs := NewFilterObserver(100)

	obs.RecordConnection("tcp", "10.0.0.1", 443, "example.com", true)
	conns := obs.GetConnections("")
	require.Len(t, conns, 1)
	require.Equal(t, "allowed", conns[0].Status)
	require.Equal(t, int64(1), conns[0].Count)

	obs.RecordConnection("tcp", "10.0.0.1", 443, "", false)
	conns = obs.GetConnections("")
	require.Len(t, conns, 1)
	require.Equal(t, "blocked", conns[0].Status)
	require.Equal(t, int64(2), conns[0].Count)
	require.Equal(t, "example.com", conns[0].SNI)
}

func TestRecordConnection_EvictsOldestAtLimit(t *testing.T) {
	obs := NewFilterObserver(3)

	obs.RecordConnection("tcp", "10.0.0.1", 80, "", true)
	obs.RecordConnection("tcp", "10.0.0.2", 80, "", true)
	obs.RecordConnection("tcp", "10.0.0.3", 80, "", true)
	require.Len(t, obs.GetConnections(""), 3)

	obs.RecordConnection("tcp", "10.0.0.4", 80, "", true)
	conns := obs.GetConnections("")
	require.Len(t, conns, 3)

	ips := make(map[string]bool)
	for _, c := range conns {
		ips[c.Key.IP] = true
	}
	require.False(t, ips["10.0.0.1"], "oldest entry should have been evicted")
	require.True(t, ips["10.0.0.4"], "new entry should be present")
}

func TestRecordConnection_UpdateDoesNotEvict(t *testing.T) {
	obs := NewFilterObserver(2)

	obs.RecordConnection("tcp", "10.0.0.1", 80, "", true)
	obs.RecordConnection("tcp", "10.0.0.2", 80, "", true)

	obs.RecordConnection("tcp", "10.0.0.1", 80, "", false)
	conns := obs.GetConnections("")
	require.Len(t, conns, 2, "updating existing entry should not evict")
}

func TestRecordDNS_EvictsOldestAtLimit(t *testing.T) {
	obs := NewFilterObserver(3)

	obs.RecordDNS("a.com", true)
	obs.RecordDNS("b.com", true)
	obs.RecordDNS("c.com", true)
	require.Len(t, obs.GetDNSQueries(""), 3)

	obs.RecordDNS("d.com", true)
	queries := obs.GetDNSQueries("")
	require.Len(t, queries, 3)

	domains := make(map[string]bool)
	for _, q := range queries {
		domains[q.Domain] = true
	}
	require.False(t, domains["a.com"], "oldest DNS entry should have been evicted")
	require.True(t, domains["d.com"], "new DNS entry should be present")
}

func TestRecordDNS_StatusRecorded(t *testing.T) {
	obs := NewFilterObserver(100)

	obs.RecordDNS("allowed.com", true)
	obs.RecordDNS("blocked.com", false)

	allowed := obs.GetDNSQueries("allowed")
	require.Len(t, allowed, 1)
	require.Equal(t, "allowed.com", allowed[0].Domain)

	blocked := obs.GetDNSQueries("blocked")
	require.Len(t, blocked, 1)
	require.Equal(t, "blocked.com", blocked[0].Domain)
}

func TestNewFilterObserver_DefaultMaxEntries(t *testing.T) {
	obs := NewFilterObserver(0)
	require.Equal(t, defaultMaxFilterHistory, obs.maxEntries)

	obs2 := NewFilterObserver(-1)
	require.Equal(t, defaultMaxFilterHistory, obs2.maxEntries)
}

func TestHasDynamicAllowlist(t *testing.T) {
	obs := NewFilterObserver(100)
	require.False(t, obs.HasDynamicAllowlist())

	obs.AddAllowlistDomain("example.com")
	require.True(t, obs.HasDynamicAllowlist())

	obs.RemoveAllowlistDomain("example.com")
	require.False(t, obs.HasDynamicAllowlist())
}

func TestDomainAllowlist_MatchesSubdomains(t *testing.T) {
	obs := NewFilterObserver(100)

	obs.AddAllowlistDomain("github.com")

	require.True(t, obs.MatchesDynamicAllowlist("github.com"))
	require.True(t, obs.MatchesDynamicAllowlist("api.github.com"))
	require.True(t, obs.MatchesDynamicAllowlist("raw.githubusercontent.github.com"))
	require.False(t, obs.MatchesDynamicAllowlist("notgithub.com"))
	require.False(t, obs.MatchesDynamicAllowlist("evil.com"))
}

func TestDomainAllowlist_AddRemoveRoundTrip(t *testing.T) {
	obs := NewFilterObserver(100)

	obs.AddAllowlistDomain("trusted.org")

	entries := obs.GetAllowlistDomains()
	require.Len(t, entries, 1)
	require.Equal(t, "trusted.org", entries[0].Domain)

	removed := obs.RemoveAllowlistDomain("trusted.org")
	require.True(t, removed)

	entries = obs.GetAllowlistDomains()
	require.Len(t, entries, 0)
}

func TestDomainAllowlist_RemoveNonexistent(t *testing.T) {
	obs := NewFilterObserver(100)

	removed := obs.RemoveAllowlistDomain("nonexistent.com")
	require.False(t, removed)
}

func TestStats_TracksConnectionCounts(t *testing.T) {
	obs := NewFilterObserver(100)

	obs.RecordConnection("tcp", "10.0.0.1", 443, "", true)
	obs.RecordConnection("tcp", "10.0.0.2", 443, "", false)
	obs.RecordConnection("udp", "10.0.0.3", 53, "", true)

	stats := obs.GetStats()
	require.Equal(t, int64(3), stats["total_connections"])
	require.Equal(t, int64(2), stats["allowed_connections"])
	require.Equal(t, int64(1), stats["blocked_connections"])
}

func TestEviction_PreservesRecentEntries(t *testing.T) {
	obs := NewFilterObserver(5)

	for i := 0; i < 10; i++ {
		obs.RecordConnection("tcp", fmt.Sprintf("10.0.0.%d", i), 80, "", true)
	}

	conns := obs.GetConnections("")
	require.Len(t, conns, 5)

	ips := make(map[string]bool)
	for _, c := range conns {
		ips[c.Key.IP] = true
	}
	for i := 5; i < 10; i++ {
		require.True(t, ips[fmt.Sprintf("10.0.0.%d", i)], "recent entry %d should be present", i)
	}
}

func TestRecordDNSResolution_PopulatesCache(t *testing.T) {
	obs := NewFilterObserver(100)

	obs.RecordDNSResolution("example.com", []string{"93.184.216.34", "93.184.216.35"})

	require.Equal(t, "example.com", obs.LookupDomain("93.184.216.34"))
	require.Equal(t, "example.com", obs.LookupDomain("93.184.216.35"))
	require.Equal(t, "", obs.LookupDomain("1.2.3.4"))
}

func TestRecordDNSResolution_OverwritesPreviousMapping(t *testing.T) {
	obs := NewFilterObserver(100)

	obs.RecordDNSResolution("old.com", []string{"1.2.3.4"})
	require.Equal(t, "old.com", obs.LookupDomain("1.2.3.4"))

	obs.RecordDNSResolution("new.com", []string{"1.2.3.4"})
	require.Equal(t, "new.com", obs.LookupDomain("1.2.3.4"))
}

func TestRecordConnection_PopulatesDomainFromSNI(t *testing.T) {
	obs := NewFilterObserver(100)

	obs.RecordConnection("tcp", "10.0.0.1", 443, "tls.example.com", true)

	conns := obs.GetConnections("")
	require.Len(t, conns, 1)
	require.Equal(t, "tls.example.com", conns[0].SNI)
	require.Equal(t, "tls.example.com", conns[0].Domain)
}

func TestRecordConnection_PopulatesDomainFromDNSCache(t *testing.T) {
	obs := NewFilterObserver(100)

	obs.RecordDNSResolution("cached.com", []string{"10.0.0.1"})
	obs.RecordConnection("tcp", "10.0.0.1", 80, "", true)

	conns := obs.GetConnections("")
	require.Len(t, conns, 1)
	require.Equal(t, "", conns[0].SNI)
	require.Equal(t, "cached.com", conns[0].Domain)
}

func TestRecordConnection_SNITakesPriorityOverDNSCache(t *testing.T) {
	obs := NewFilterObserver(100)

	obs.RecordDNSResolution("cached.com", []string{"10.0.0.1"})
	obs.RecordConnection("tcp", "10.0.0.1", 443, "sni.example.com", true)

	conns := obs.GetConnections("")
	require.Len(t, conns, 1)
	require.Equal(t, "sni.example.com", conns[0].SNI)
	require.Equal(t, "sni.example.com", conns[0].Domain)
}

func TestDomainBlocklist_AddRemoveRoundTrip(t *testing.T) {
	obs := NewFilterObserver(100)

	obs.AddDomainBlocklistEntry("evil.com", "malicious")

	entries := obs.GetDomainBlocklistEntries()
	require.Len(t, entries, 1)
	require.Equal(t, "evil.com", entries[0].Domain)
	require.Equal(t, "malicious", entries[0].Reason)

	removed := obs.RemoveDomainBlocklistEntry("evil.com")
	require.True(t, removed)

	entries = obs.GetDomainBlocklistEntries()
	require.Len(t, entries, 0)
}

func TestDomainBlocklist_RemoveNonexistent(t *testing.T) {
	obs := NewFilterObserver(100)

	removed := obs.RemoveDomainBlocklistEntry("nonexistent.com")
	require.False(t, removed)
}

func TestIsBlocked_ByDomainExact(t *testing.T) {
	obs := NewFilterObserver(100)

	obs.RecordDNSResolution("blocked.com", []string{"10.0.0.1"})
	obs.AddDomainBlocklistEntry("blocked.com", "test")

	require.True(t, obs.IsBlocked("tcp", "10.0.0.1", 443))
	require.True(t, obs.IsBlocked("tcp", "10.0.0.1", 80))
	require.True(t, obs.IsBlocked("udp", "10.0.0.1", 53))
	require.False(t, obs.IsBlocked("tcp", "10.0.0.2", 443))
}

func TestIsBlocked_ByDomainMatchesSubdomains(t *testing.T) {
	obs := NewFilterObserver(100)

	obs.RecordDNSResolution("www.google.com", []string{"10.0.0.1"})
	obs.RecordDNSResolution("mail.google.com", []string{"10.0.0.2"})
	obs.RecordDNSResolution("google.com", []string{"10.0.0.3"})
	obs.RecordDNSResolution("notgoogle.com", []string{"10.0.0.4"})

	obs.AddDomainBlocklistEntry("google.com", "test")

	require.True(t, obs.IsBlocked("tcp", "10.0.0.1", 443), "www.google.com should be blocked")
	require.True(t, obs.IsBlocked("tcp", "10.0.0.2", 443), "mail.google.com should be blocked")
	require.True(t, obs.IsBlocked("tcp", "10.0.0.3", 443), "google.com should be blocked")
	require.False(t, obs.IsBlocked("tcp", "10.0.0.4", 443), "notgoogle.com should not be blocked")
}

func TestIsBlocked_DomainAndIPCoexist(t *testing.T) {
	obs := NewFilterObserver(100)

	obs.AddBlocklistEntry("tcp", "10.0.0.1", 443, "ip-blocked")
	obs.RecordDNSResolution("domain-blocked.com", []string{"10.0.0.2"})
	obs.AddDomainBlocklistEntry("domain-blocked.com", "domain-blocked")

	require.True(t, obs.IsBlocked("tcp", "10.0.0.1", 443))
	require.False(t, obs.IsBlocked("tcp", "10.0.0.1", 80))
	require.True(t, obs.IsBlocked("tcp", "10.0.0.2", 443))
	require.True(t, obs.IsBlocked("tcp", "10.0.0.2", 80))
}

func TestGetStats_IncludesDomainBlocklistCount(t *testing.T) {
	obs := NewFilterObserver(100)

	obs.AddBlocklistEntry("tcp", "10.0.0.1", 443, "ip")
	obs.AddDomainBlocklistEntry("evil.com", "domain")

	stats := obs.GetStats()
	require.Equal(t, 2, stats["blocklist_entries"])
}
