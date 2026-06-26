package filter

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Mux returns the HTTP handler for the filter API
func (f *FilterObserver) Mux() http.Handler {
	mux := http.NewServeMux()

	// Connection endpoints
	mux.HandleFunc("/connections", f.handleConnections)
	mux.HandleFunc("/connections/blocked", f.handleConnectionsBlocked)
	mux.HandleFunc("/connections/allowed", f.handleConnectionsAllowed)

	// DNS endpoints
	mux.HandleFunc("/dns/queries", f.handleDNSQueries)
	mux.HandleFunc("/dns/blocked", f.handleDNSBlocked)

	// Allowlist endpoints
	mux.HandleFunc("/allowlist", f.handleAllowlist)

	// Blocklist endpoints
	mux.HandleFunc("/blocklist", f.handleBlocklist)

	// Stats endpoint
	mux.HandleFunc("/stats", f.handleStats)

	// History endpoint
	mux.HandleFunc("/history", f.handleHistory)

	// SSE events endpoint
	mux.HandleFunc("/events", f.handleEvents)

	return mux
}

// handleConnections handles GET /connections
func (f *FilterObserver) handleConnections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	connections := f.GetConnections("")
	response := map[string]interface{}{
		"connections": connectionsToJSON(connections),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
}

// handleConnectionsBlocked handles GET /connections/blocked
func (f *FilterObserver) handleConnectionsBlocked(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	connections := f.GetConnections("blocked")
	response := map[string]interface{}{
		"connections": connectionsToJSON(connections),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
}

// handleConnectionsAllowed handles GET /connections/allowed
func (f *FilterObserver) handleConnectionsAllowed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	connections := f.GetConnections("allowed")
	response := map[string]interface{}{
		"connections": connectionsToJSON(connections),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
}

// handleDNSQueries handles GET /dns/queries
func (f *FilterObserver) handleDNSQueries(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	queries := f.GetDNSQueries("")
	response := map[string]interface{}{
		"queries": dnsQueriesToJSON(queries),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
}

// handleDNSBlocked handles GET /dns/blocked
func (f *FilterObserver) handleDNSBlocked(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	queries := f.GetDNSQueries("blocked")
	response := map[string]interface{}{
		"queries": dnsQueriesToJSON(queries),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
}

// handleAllowlist handles GET/POST/DELETE /allowlist
func (f *FilterObserver) handleAllowlist(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		f.handleAllowlistGet(w, r)
	case http.MethodPost:
		f.handleAllowlistPost(w, r)
	case http.MethodDelete:
		f.handleAllowlistDelete(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAllowlistGet handles GET /allowlist
func (f *FilterObserver) handleAllowlistGet(w http.ResponseWriter, r *http.Request) {
	domains := f.GetAllowlistDomains()
	configPatterns := f.GetConfigAllowlistPatterns()

	response := map[string]interface{}{
		"domains":         domainAllowlistToJSON(domains),
		"config_patterns": configPatterns,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
}

// handleAllowlistPost handles POST /allowlist
func (f *FilterObserver) handleAllowlistPost(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Domain == "" {
		http.Error(w, "domain is required", http.StatusBadRequest)
		return
	}

	f.AddAllowlistDomain(req.Domain)

	response := map[string]interface{}{
		"success": true,
		"domain":  req.Domain,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
}

// handleAllowlistDelete handles DELETE /allowlist
func (f *FilterObserver) handleAllowlistDelete(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Domain == "" {
		http.Error(w, "domain is required", http.StatusBadRequest)
		return
	}

	removed := f.RemoveAllowlistDomain(req.Domain)
	response := map[string]interface{}{
		"success": removed,
		"removed": removed,
	}

	if !removed {
		response["note"] = "Domain not found in dynamic allowlist"
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
}

// handleBlocklist handles GET/POST/DELETE /blocklist
func (f *FilterObserver) handleBlocklist(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		f.handleBlocklistGet(w, r)
	case http.MethodPost:
		f.handleBlocklistPost(w, r)
	case http.MethodDelete:
		f.handleBlocklistDelete(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleBlocklistGet handles GET /blocklist
func (f *FilterObserver) handleBlocklistGet(w http.ResponseWriter, r *http.Request) {
	entries := f.GetBlocklistEntries()
	domainEntries := f.GetDomainBlocklistEntries()
	response := map[string]interface{}{
		"entries":        blocklistToJSON(entries),
		"domain_entries": domainBlocklistToJSON(domainEntries),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
}

// handleBlocklistPost handles POST /blocklist
func (f *FilterObserver) handleBlocklistPost(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var req struct {
		Protocol string `json:"protocol"`
		IP       string `json:"ip"`
		Port     uint16 `json:"port"`
		Domain   string `json:"domain"`
		Reason   string `json:"reason"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Domain != "" {
		f.AddDomainBlocklistEntry(req.Domain, req.Reason)

		response := map[string]interface{}{
			"success": true,
			"blocked": true,
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
			return
		}
		return
	}

	if req.Protocol == "" || req.IP == "" || req.Port == 0 {
		http.Error(w, "protocol/ip/port or domain is required", http.StatusBadRequest)
		return
	}

	if req.Protocol != "tcp" && req.Protocol != "udp" {
		http.Error(w, "protocol must be tcp or udp", http.StatusBadRequest)
		return
	}

	f.AddBlocklistEntry(req.Protocol, req.IP, req.Port, req.Reason)

	response := map[string]interface{}{
		"success": true,
		"blocked": true,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
}

// handleBlocklistDelete handles DELETE /blocklist
func (f *FilterObserver) handleBlocklistDelete(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var req struct {
		Protocol string `json:"protocol"`
		IP       string `json:"ip"`
		Port     uint16 `json:"port"`
		Domain   string `json:"domain"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Domain != "" {
		removed := f.RemoveDomainBlocklistEntry(req.Domain)
		response := map[string]interface{}{
			"success": removed,
			"removed": removed,
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
			return
		}
		return
	}

	if req.Protocol == "" || req.IP == "" || req.Port == 0 {
		http.Error(w, "protocol/ip/port or domain is required", http.StatusBadRequest)
		return
	}

	removed := f.RemoveBlocklistEntry(req.Protocol, req.IP, req.Port)
	response := map[string]interface{}{
		"success": removed,
		"removed": removed,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
}

// handleStats handles GET /stats
func (f *FilterObserver) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := f.GetStats()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(stats); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
}

// handleHistory handles DELETE /history
func (f *FilterObserver) handleHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	connectionCount, dnsCount := f.ClearHistory()

	response := map[string]interface{}{
		"success": true,
		"cleared": map[string]int{
			"connections": connectionCount,
			"dns_queries": dnsCount,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
}

// handleEvents handles GET /events (Server-Sent Events)
func (f *FilterObserver) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Set headers for SSE
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// Create subscriber
	ch := f.Subscribe()
	defer f.Unsubscribe(ch)

	// Get flusher
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	// Send events
	for {
		select {
		case event, ok := <-ch:
			if !ok {
				return
			}

			sseData, err := FormatSSE(event)
			if err != nil {
				continue
			}

			fmt.Fprint(w, sseData)
			flusher.Flush()

		case <-r.Context().Done():
			return
		}
	}
}

// Helper functions to convert structs to JSON-friendly maps

func connectionsToJSON(connections []*ConnectionRecord) []map[string]interface{} {
	var result []map[string]interface{}
	for _, conn := range connections {
		result = append(result, map[string]interface{}{
			"protocol":         conn.Key.Protocol,
			"destination_ip":   conn.Key.IP,
			"destination_port": conn.Key.Port,
			"sni":              conn.SNI,
			"domain":           conn.Domain,
			"status":           conn.Status,
			"count":            conn.Count,
			"first_seen":       conn.FirstSeen.Format("2006-01-02T15:04:05Z07:00"),
			"last_seen":        conn.LastSeen.Format("2006-01-02T15:04:05Z07:00"),
		})
	}
	return result
}

func dnsQueriesToJSON(queries []*DNSRecord) []map[string]interface{} {
	var result []map[string]interface{}
	for _, query := range queries {
		result = append(result, map[string]interface{}{
			"domain":     query.Domain,
			"status":     query.Status,
			"count":      query.Count,
			"first_seen": query.FirstSeen.Format("2006-01-02T15:04:05Z07:00"),
			"last_seen":  query.LastSeen.Format("2006-01-02T15:04:05Z07:00"),
		})
	}
	return result
}

func blocklistToJSON(entries []*BlocklistEntry) []map[string]interface{} {
	var result []map[string]interface{}
	for _, entry := range entries {
		result = append(result, map[string]interface{}{
			"protocol": entry.Protocol,
			"ip":       entry.IP,
			"port":     entry.Port,
			"added_at": entry.AddedAt.Format("2006-01-02T15:04:05Z07:00"),
			"reason":   entry.Reason,
		})
	}
	return result
}

func domainAllowlistToJSON(entries []*DomainAllowlistEntry) []map[string]interface{} {
	var result []map[string]interface{}
	for _, entry := range entries {
		result = append(result, map[string]interface{}{
			"domain":   entry.Domain,
			"added_at": entry.AddedAt.Format("2006-01-02T15:04:05Z07:00"),
		})
	}
	return result
}

func domainBlocklistToJSON(entries []*DomainBlocklistEntry) []map[string]interface{} {
	var result []map[string]interface{}
	for _, entry := range entries {
		result = append(result, map[string]interface{}{
			"domain":   entry.Domain,
			"added_at": entry.AddedAt.Format("2006-01-02T15:04:05Z07:00"),
			"reason":   entry.Reason,
		})
	}
	return result
}
