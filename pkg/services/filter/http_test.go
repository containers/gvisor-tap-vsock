package filter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func newTestServer(t *testing.T) (*FilterObserver, *httptest.Server) {
	t.Helper()
	obs := NewFilterObserver(100)
	srv := httptest.NewServer(obs.Mux())
	t.Cleanup(srv.Close)
	return obs, srv
}

func getJSON(t *testing.T, url string) map[string]interface{} {
	t.Helper()
	resp, err := http.Get(url) // #nosec G107
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	return result
}

func doRequest(t *testing.T, method, url, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

func TestHTTP_GetConnections_Empty(t *testing.T) {
	_, srv := newTestServer(t)

	result := getJSON(t, srv.URL+"/connections")
	require.Nil(t, result["connections"])
}

func TestHTTP_GetConnections_Populated(t *testing.T) {
	obs, srv := newTestServer(t)

	obs.RecordConnection("tcp", "10.0.0.1", 443, "example.com", true)
	obs.RecordConnection("tcp", "10.0.0.2", 80, "", false)

	result := getJSON(t, srv.URL+"/connections")
	connections := result["connections"].([]interface{})
	require.Len(t, connections, 2)
}

func TestHTTP_GetConnectionsBlocked(t *testing.T) {
	obs, srv := newTestServer(t)

	obs.RecordConnection("tcp", "10.0.0.1", 443, "good.com", true)
	obs.RecordConnection("tcp", "10.0.0.2", 80, "", false)

	result := getJSON(t, srv.URL+"/connections/blocked")
	connections := result["connections"].([]interface{})
	require.Len(t, connections, 1)
	conn := connections[0].(map[string]interface{})
	require.Equal(t, "blocked", conn["status"])
	require.Equal(t, "10.0.0.2", conn["destination_ip"])
}

func TestHTTP_GetConnectionsAllowed(t *testing.T) {
	obs, srv := newTestServer(t)

	obs.RecordConnection("tcp", "10.0.0.1", 443, "good.com", true)
	obs.RecordConnection("tcp", "10.0.0.2", 80, "", false)

	result := getJSON(t, srv.URL+"/connections/allowed")
	connections := result["connections"].([]interface{})
	require.Len(t, connections, 1)
	conn := connections[0].(map[string]interface{})
	require.Equal(t, "allowed", conn["status"])
	require.Equal(t, "good.com", conn["sni"])
}

func TestHTTP_GetDNSQueries(t *testing.T) {
	obs, srv := newTestServer(t)

	obs.RecordDNS("example.com", true)
	obs.RecordDNS("blocked.com", false)

	result := getJSON(t, srv.URL+"/dns/queries")
	queries := result["queries"].([]interface{})
	require.Len(t, queries, 2)
}

func TestHTTP_GetDNSBlocked(t *testing.T) {
	obs, srv := newTestServer(t)

	obs.RecordDNS("example.com", true)
	obs.RecordDNS("blocked.com", false)

	result := getJSON(t, srv.URL+"/dns/blocked")
	queries := result["queries"].([]interface{})
	require.Len(t, queries, 1)
	q := queries[0].(map[string]interface{})
	require.Equal(t, "blocked.com", q["domain"])
	require.Equal(t, "blocked", q["status"])
}

func TestHTTP_AllowlistRoundTrip(t *testing.T) {
	_, srv := newTestServer(t)

	// Initially empty
	result := getJSON(t, srv.URL+"/allowlist")
	require.Nil(t, result["domains"])

	// Add a domain
	resp := doRequest(t, http.MethodPost, srv.URL+"/allowlist", `{"domain":"example.com"}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var addResult map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&addResult))
	require.Equal(t, true, addResult["success"])
	require.Equal(t, "example.com", addResult["domain"])

	// Verify it appears in GET
	result = getJSON(t, srv.URL+"/allowlist")
	domains := result["domains"]
	require.NotNil(t, domains)
	domainList := domains.([]interface{})
	require.Len(t, domainList, 1)
	entry := domainList[0].(map[string]interface{})
	require.Equal(t, "example.com", entry["domain"])
	require.NotEmpty(t, entry["added_at"])

	// Delete the domain
	resp2 := doRequest(t, http.MethodDelete, srv.URL+"/allowlist", `{"domain":"example.com"}`)
	defer resp2.Body.Close()
	require.Equal(t, http.StatusOK, resp2.StatusCode)
	var delResult map[string]interface{}
	require.NoError(t, json.NewDecoder(resp2.Body).Decode(&delResult))
	require.Equal(t, true, delResult["success"])
	require.Equal(t, true, delResult["removed"])

	// Verify it's gone
	result = getJSON(t, srv.URL+"/allowlist")
	require.Nil(t, result["domains"])
}

func TestHTTP_AllowlistConfigPatternsVisible(t *testing.T) {
	obs, srv := newTestServer(t)

	compiled := regexp.MustCompile(`^config\.example\.com$`)
	obs.SetConfigAllowlist([]*regexp.Regexp{compiled})

	result := getJSON(t, srv.URL+"/allowlist")
	configPatterns := result["config_patterns"].([]interface{})
	require.Len(t, configPatterns, 1)
	require.Equal(t, `^config\.example\.com$`, configPatterns[0])
}

func TestHTTP_AllowlistDeleteNonexistent(t *testing.T) {
	_, srv := newTestServer(t)

	resp := doRequest(t, http.MethodDelete, srv.URL+"/allowlist", `{"domain":"nonexistent.com"}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var result map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	require.Equal(t, false, result["success"])
	require.Equal(t, false, result["removed"])
}

func TestHTTP_BlocklistRoundTrip(t *testing.T) {
	_, srv := newTestServer(t)

	// Initially empty
	result := getJSON(t, srv.URL+"/blocklist")
	require.Nil(t, result["entries"])

	// Add an entry
	resp := doRequest(t, http.MethodPost, srv.URL+"/blocklist",
		`{"protocol":"tcp","ip":"10.0.0.5","port":443,"reason":"suspicious"}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var addResult map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&addResult))
	require.Equal(t, true, addResult["success"])
	require.Equal(t, true, addResult["blocked"])

	// Verify it appears in GET
	result = getJSON(t, srv.URL+"/blocklist")
	entries := result["entries"].([]interface{})
	require.Len(t, entries, 1)
	entry := entries[0].(map[string]interface{})
	require.Equal(t, "tcp", entry["protocol"])
	require.Equal(t, "10.0.0.5", entry["ip"])
	require.Equal(t, float64(443), entry["port"])
	require.Equal(t, "suspicious", entry["reason"])

	// Delete the entry
	resp2 := doRequest(t, http.MethodDelete, srv.URL+"/blocklist",
		`{"protocol":"tcp","ip":"10.0.0.5","port":443}`)
	defer resp2.Body.Close()
	require.Equal(t, http.StatusOK, resp2.StatusCode)
	var delResult map[string]interface{}
	require.NoError(t, json.NewDecoder(resp2.Body).Decode(&delResult))
	require.Equal(t, true, delResult["success"])
	require.Equal(t, true, delResult["removed"])

	// Verify it's gone
	result = getJSON(t, srv.URL+"/blocklist")
	require.Nil(t, result["entries"])
}

func TestHTTP_BlocklistDeleteNonexistent(t *testing.T) {
	_, srv := newTestServer(t)

	resp := doRequest(t, http.MethodDelete, srv.URL+"/blocklist",
		`{"protocol":"tcp","ip":"10.0.0.99","port":8080}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var result map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	require.Equal(t, false, result["success"])
	require.Equal(t, false, result["removed"])
}

func TestHTTP_Stats(t *testing.T) {
	obs, srv := newTestServer(t)

	obs.RecordConnection("tcp", "10.0.0.1", 443, "", true)
	obs.RecordConnection("tcp", "10.0.0.2", 443, "", false)
	obs.RecordDNS("example.com", true)
	obs.RecordDNS("blocked.com", false)

	result := getJSON(t, srv.URL+"/stats")
	require.Equal(t, float64(2), result["total_connections"])
	require.Equal(t, float64(1), result["allowed_connections"])
	require.Equal(t, float64(1), result["blocked_connections"])
	require.Equal(t, float64(2), result["total_dns_queries"])
	require.Equal(t, float64(1), result["blocked_dns_queries"])
}

func TestHTTP_DeleteHistory(t *testing.T) {
	obs, srv := newTestServer(t)

	obs.RecordConnection("tcp", "10.0.0.1", 443, "", true)
	obs.RecordConnection("tcp", "10.0.0.2", 80, "", false)
	obs.RecordDNS("example.com", true)

	resp := doRequest(t, http.MethodDelete, srv.URL+"/history", "")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	require.Equal(t, true, result["success"])
	cleared := result["cleared"].(map[string]interface{})
	require.Equal(t, float64(2), cleared["connections"])
	require.Equal(t, float64(1), cleared["dns_queries"])

	// Verify cleared
	conns := getJSON(t, srv.URL+"/connections")
	require.Nil(t, conns["connections"])
	dns := getJSON(t, srv.URL+"/dns/queries")
	require.Nil(t, dns["queries"])
}

func TestHTTP_MethodNotAllowed(t *testing.T) {
	_, srv := newTestServer(t)

	tests := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/connections"},
		{http.MethodPost, "/connections/blocked"},
		{http.MethodPost, "/connections/allowed"},
		{http.MethodPost, "/dns/queries"},
		{http.MethodPost, "/dns/blocked"},
		{http.MethodPost, "/stats"},
		{http.MethodGet, "/history"},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			resp := doRequest(t, tt.method, srv.URL+tt.path, "")
			defer resp.Body.Close()
			require.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
		})
	}
}

func TestHTTP_BlocklistInvalidJSON(t *testing.T) {
	_, srv := newTestServer(t)

	resp := doRequest(t, http.MethodPost, srv.URL+"/blocklist", "not json")
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHTTP_BlocklistMissingFields(t *testing.T) {
	_, srv := newTestServer(t)

	resp := doRequest(t, http.MethodPost, srv.URL+"/blocklist", `{"protocol":"tcp"}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHTTP_BlocklistInvalidProtocol(t *testing.T) {
	_, srv := newTestServer(t)

	resp := doRequest(t, http.MethodPost, srv.URL+"/blocklist",
		`{"protocol":"icmp","ip":"10.0.0.1","port":443}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHTTP_AllowlistMissingDomain(t *testing.T) {
	_, srv := newTestServer(t)

	resp := doRequest(t, http.MethodPost, srv.URL+"/allowlist", `{}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHTTP_ConnectionFields(t *testing.T) {
	obs, srv := newTestServer(t)

	obs.RecordConnection("tcp", "142.250.80.46", 443, "www.google.com", true)

	result := getJSON(t, srv.URL+"/connections")
	connections := result["connections"].([]interface{})
	require.Len(t, connections, 1)
	conn := connections[0].(map[string]interface{})

	require.Equal(t, "tcp", conn["protocol"])
	require.Equal(t, "142.250.80.46", conn["destination_ip"])
	require.Equal(t, float64(443), conn["destination_port"])
	require.Equal(t, "www.google.com", conn["sni"])
	require.Equal(t, "allowed", conn["status"])
	require.Equal(t, float64(1), conn["count"])
	require.NotEmpty(t, conn["first_seen"])
	require.NotEmpty(t, conn["last_seen"])
}

func TestHTTP_DNSQueryFields(t *testing.T) {
	obs, srv := newTestServer(t)

	obs.RecordDNS("example.com", true)

	result := getJSON(t, srv.URL+"/dns/queries")
	queries := result["queries"].([]interface{})
	require.Len(t, queries, 1)
	q := queries[0].(map[string]interface{})

	require.Equal(t, "example.com", q["domain"])
	require.Equal(t, "allowed", q["status"])
	require.Equal(t, float64(1), q["count"])
	require.NotEmpty(t, q["first_seen"])
	require.NotEmpty(t, q["last_seen"])
}

func TestHTTP_StatsIncludeAllowlistBlocklistCounts(t *testing.T) {
	obs, srv := newTestServer(t)

	obs.AddAllowlistDomain("test.com")
	obs.AddBlocklistEntry("tcp", "10.0.0.1", 443, "test")

	result := getJSON(t, srv.URL+"/stats")
	require.Equal(t, float64(1), result["allowlist_patterns"])
	require.Equal(t, float64(1), result["blocklist_entries"])
}

func TestHTTP_ConnectionDomainField(t *testing.T) {
	obs, srv := newTestServer(t)

	obs.RecordDNSResolution("dns-resolved.com", []string{"10.0.0.1"})
	obs.RecordConnection("tcp", "10.0.0.1", 80, "", true)
	obs.RecordConnection("tcp", "10.0.0.2", 443, "sni.example.com", true)

	result := getJSON(t, srv.URL+"/connections")
	connections := result["connections"].([]interface{})
	require.Len(t, connections, 2)

	domains := make(map[string]string)
	for _, c := range connections {
		conn := c.(map[string]interface{})
		ip := conn["destination_ip"].(string)
		domain, _ := conn["domain"].(string)
		domains[ip] = domain
	}
	require.Equal(t, "dns-resolved.com", domains["10.0.0.1"])
	require.Equal(t, "sni.example.com", domains["10.0.0.2"])
}

func TestHTTP_DomainBlocklistRoundTrip(t *testing.T) {
	_, srv := newTestServer(t)

	// Add domain
	resp := doRequest(t, http.MethodPost, srv.URL+"/blocklist",
		`{"domain":"evil.com","reason":"malicious"}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var addResult map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&addResult))
	require.Equal(t, true, addResult["success"])

	// Verify it appears in GET
	result := getJSON(t, srv.URL+"/blocklist")
	domainEntries := result["domain_entries"].([]interface{})
	require.Len(t, domainEntries, 1)
	entry := domainEntries[0].(map[string]interface{})
	require.Equal(t, "evil.com", entry["domain"])
	require.Equal(t, "malicious", entry["reason"])

	// IP entries should be empty
	require.Nil(t, result["entries"])

	// Delete domain
	resp2 := doRequest(t, http.MethodDelete, srv.URL+"/blocklist",
		`{"domain":"evil.com"}`)
	defer resp2.Body.Close()
	require.Equal(t, http.StatusOK, resp2.StatusCode)
	var delResult map[string]interface{}
	require.NoError(t, json.NewDecoder(resp2.Body).Decode(&delResult))
	require.Equal(t, true, delResult["success"])

	// Verify it's gone
	result = getJSON(t, srv.URL+"/blocklist")
	require.Nil(t, result["domain_entries"])
}

func TestHTTP_BlocklistMixedIPAndDomain(t *testing.T) {
	_, srv := newTestServer(t)

	// Add IP entry
	resp := doRequest(t, http.MethodPost, srv.URL+"/blocklist",
		`{"protocol":"tcp","ip":"10.0.0.5","port":443,"reason":"ip-blocked"}`)
	resp.Body.Close()

	// Add domain
	resp = doRequest(t, http.MethodPost, srv.URL+"/blocklist",
		`{"domain":"evil.com","reason":"domain-blocked"}`)
	resp.Body.Close()

	result := getJSON(t, srv.URL+"/blocklist")

	entries := result["entries"].([]interface{})
	require.Len(t, entries, 1)
	require.Equal(t, "10.0.0.5", entries[0].(map[string]interface{})["ip"])

	domainEntries := result["domain_entries"].([]interface{})
	require.Len(t, domainEntries, 1)
	require.Equal(t, "evil.com", domainEntries[0].(map[string]interface{})["domain"])
}

func TestHTTP_DomainBlocklistDeleteNonexistent(t *testing.T) {
	_, srv := newTestServer(t)

	resp := doRequest(t, http.MethodDelete, srv.URL+"/blocklist",
		`{"domain":"nonexistent.com"}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var result map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	require.Equal(t, false, result["success"])
	require.Equal(t, false, result["removed"])
}
