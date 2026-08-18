package filter

import (
	"regexp"
	"sync"
	"time"
)

// ConnectionKey uniquely identifies a connection by protocol, IP, and port
type ConnectionKey struct {
	Protocol string
	IP       string
	Port     uint16
}

// ConnectionRecord tracks connection attempts with aggregated statistics
type ConnectionRecord struct {
	Key       ConnectionKey
	SNI       string
	Domain    string
	Status    string
	Count     int64
	FirstSeen time.Time
	LastSeen  time.Time
}

// DNSRecord tracks DNS query attempts with aggregated statistics
type DNSRecord struct {
	Domain    string
	Status    string
	Count     int64
	FirstSeen time.Time
	LastSeen  time.Time
}

// BlocklistEntry represents a dynamically blocked connection
type BlocklistEntry struct {
	Protocol string
	IP       string
	Port     uint16
	AddedAt  time.Time
	Reason   string
}

// DomainBlocklistEntry represents a dynamically blocked domain.
// Blocking "example.com" matches both "example.com" and "*.example.com".
type DomainBlocklistEntry struct {
	Domain   string
	compiled *regexp.Regexp
	AddedAt  time.Time
	Reason   string
}

// DomainAllowlistEntry represents a dynamically allowed domain.
// Allowing "example.com" matches both "example.com" and "*.example.com".
type DomainAllowlistEntry struct {
	Domain   string
	compiled *regexp.Regexp
	AddedAt  time.Time
}

// ConfigAllowlistEntry represents a config-sourced allowlist pattern (for display only;
// actual matching uses the []*regexp.Regexp passed to the DNS handler directly)
type ConfigAllowlistEntry struct {
	Pattern string
	AddedAt time.Time
}

const defaultMaxFilterHistory = 10000

// FilterObserver tracks connection and DNS filtering decisions
type FilterObserver struct {
	mu          sync.RWMutex
	connections map[ConnectionKey]*ConnectionRecord
	dnsQueries  map[string]*DNSRecord
	maxEntries  int

	// IP→domain reverse lookup cache (populated from DNS resolutions)
	dnsCache map[string]string

	// Dynamic filtering state
	dynamicAllowlist   map[string]*DomainAllowlistEntry
	dynamicAllowlistMu sync.RWMutex
	configAllowlist    map[string]*ConfigAllowlistEntry
	dynamicBlocklist   map[ConnectionKey]*BlocklistEntry
	domainBlocklist    map[string]*DomainBlocklistEntry
	dynamicBlocklistMu sync.RWMutex

	// SSE subscribers
	subscribers   map[chan Event]bool
	subscribersMu sync.RWMutex

	// Statistics
	stats struct {
		sync.RWMutex
		TotalConnections   int64
		BlockedConnections int64
		AllowedConnections int64
		TotalDNSQueries    int64
		BlockedDNSQueries  int64
		StartTime          time.Time
	}
}

// NewFilterObserver creates a new FilterObserver instance.
// maxEntries caps the number of connection and DNS records kept;
// zero or negative values fall back to defaultMaxFilterHistory.
func NewFilterObserver(maxEntries int) *FilterObserver {
	if maxEntries <= 0 {
		maxEntries = defaultMaxFilterHistory
	}
	f := &FilterObserver{
		connections:      make(map[ConnectionKey]*ConnectionRecord),
		dnsQueries:       make(map[string]*DNSRecord),
		maxEntries:       maxEntries,
		dnsCache:         make(map[string]string),
		dynamicAllowlist: make(map[string]*DomainAllowlistEntry),
		configAllowlist:  make(map[string]*ConfigAllowlistEntry),
		dynamicBlocklist: make(map[ConnectionKey]*BlocklistEntry),
		domainBlocklist:  make(map[string]*DomainBlocklistEntry),
		subscribers:      make(map[chan Event]bool),
	}
	f.stats.StartTime = time.Now()
	return f
}

// RecordConnection records a connection attempt (called from TCP/UDP forwarders)
func (f *FilterObserver) RecordConnection(protocol, ip string, port uint16, sni string, allowed bool) {
	key := ConnectionKey{
		Protocol: protocol,
		IP:       ip,
		Port:     port,
	}

	now := time.Now()
	status := "allowed"
	if !allowed {
		status = "blocked"
	}

	domain := sni
	if domain == "" {
		domain = f.LookupDomain(ip)
	}

	f.mu.Lock()
	record, exists := f.connections[key]
	if exists {
		record.Count++
		record.LastSeen = now
		record.Status = status
		if sni != "" && record.SNI == "" {
			record.SNI = sni
		}
		if domain != "" && record.Domain == "" {
			record.Domain = domain
		}
	} else {
		if len(f.connections) >= f.maxEntries {
			f.evictOldestConnection()
		}
		record = &ConnectionRecord{
			Key:       key,
			SNI:       sni,
			Domain:    domain,
			Status:    status,
			Count:     1,
			FirstSeen: now,
			LastSeen:  now,
		}
		f.connections[key] = record
	}
	f.mu.Unlock()

	// Update statistics
	f.stats.Lock()
	f.stats.TotalConnections++
	if allowed {
		f.stats.AllowedConnections++
	} else {
		f.stats.BlockedConnections++
	}
	f.stats.Unlock()

	// Publish SSE event
	eventType := "connection_allowed"
	reason := "allowlist match"
	if !allowed {
		eventType = "connection_blocked"
		reason = "not in allowlist"
		if f.IsBlocked(protocol, ip, port) {
			reason = "dynamic blocklist"
		}
	}

	f.publishEvent(eventType, map[string]interface{}{
		"protocol": protocol,
		"ip":       ip,
		"port":     port,
		"sni":      sni,
		"reason":   reason,
	})
}

// RecordDNS records a DNS query attempt (called from DNS handler)
func (f *FilterObserver) RecordDNS(domain string, allowed bool) {
	now := time.Now()
	status := "allowed"
	if !allowed {
		status = "blocked"
	}

	f.mu.Lock()
	record, exists := f.dnsQueries[domain]
	if exists {
		record.Count++
		record.LastSeen = now
	} else {
		if len(f.dnsQueries) >= f.maxEntries {
			f.evictOldestDNS()
		}
		record = &DNSRecord{
			Domain:    domain,
			Status:    status,
			Count:     1,
			FirstSeen: now,
			LastSeen:  now,
		}
		f.dnsQueries[domain] = record
	}
	f.mu.Unlock()

	// Update statistics
	f.stats.Lock()
	f.stats.TotalDNSQueries++
	if !allowed {
		f.stats.BlockedDNSQueries++
	}
	f.stats.Unlock()

	// Publish SSE event
	eventType := "dns_allowed"
	if !allowed {
		eventType = "dns_blocked"
	}

	f.publishEvent(eventType, map[string]interface{}{
		"domain": domain,
		"status": status,
	})
}

// IsBlocked checks if a connection is in the dynamic blocklist (by IP:port or domain pattern)
func (f *FilterObserver) IsBlocked(protocol, ip string, port uint16) bool {
	key := ConnectionKey{
		Protocol: protocol,
		IP:       ip,
		Port:     port,
	}

	f.dynamicBlocklistMu.RLock()
	_, blocked := f.dynamicBlocklist[key]
	if !blocked {
		domain := f.lookupDomainLocked(ip)
		if domain != "" {
			for _, entry := range f.domainBlocklist {
				if entry.compiled.MatchString(domain) {
					blocked = true
					break
				}
			}
		}
	}
	f.dynamicBlocklistMu.RUnlock()

	return blocked
}

// MatchesDynamicAllowlist checks if a domain matches any dynamic allowlist entry
func (f *FilterObserver) MatchesDynamicAllowlist(domain string) bool {
	f.dynamicAllowlistMu.RLock()
	defer f.dynamicAllowlistMu.RUnlock()

	for _, entry := range f.dynamicAllowlist {
		if entry.compiled.MatchString(domain) {
			return true
		}
	}
	return false
}

// AddAllowlistDomain adds a domain to the dynamic allowlist.
// Allowing "example.com" also allows "*.example.com".
func (f *FilterObserver) AddAllowlistDomain(domain string) {
	compiled := regexp.MustCompile(`(^|\.)` + regexp.QuoteMeta(domain) + `$`)

	f.dynamicAllowlistMu.Lock()
	f.dynamicAllowlist[domain] = &DomainAllowlistEntry{
		Domain:   domain,
		compiled: compiled,
		AddedAt:  time.Now(),
	}
	f.dynamicAllowlistMu.Unlock()

	f.publishEvent("allowlist_updated", map[string]interface{}{
		"action": "added",
		"domain": domain,
	})
}

// RemoveAllowlistDomain removes a domain from the dynamic allowlist
func (f *FilterObserver) RemoveAllowlistDomain(domain string) bool {
	f.dynamicAllowlistMu.Lock()
	_, exists := f.dynamicAllowlist[domain]
	if exists {
		delete(f.dynamicAllowlist, domain)
	}
	f.dynamicAllowlistMu.Unlock()

	if exists {
		f.publishEvent("allowlist_updated", map[string]interface{}{
			"action": "removed",
			"domain": domain,
		})
	}

	return exists
}

// AddBlocklistEntry adds an entry to the dynamic blocklist
func (f *FilterObserver) AddBlocklistEntry(protocol, ip string, port uint16, reason string) {
	key := ConnectionKey{
		Protocol: protocol,
		IP:       ip,
		Port:     port,
	}

	f.dynamicBlocklistMu.Lock()
	f.dynamicBlocklist[key] = &BlocklistEntry{
		Protocol: protocol,
		IP:       ip,
		Port:     port,
		AddedAt:  time.Now(),
		Reason:   reason,
	}
	f.dynamicBlocklistMu.Unlock()

	f.publishEvent("blocklist_updated", map[string]interface{}{
		"action":   "added",
		"protocol": protocol,
		"ip":       ip,
		"port":     port,
		"reason":   reason,
	})
}

// RemoveBlocklistEntry removes an entry from the dynamic blocklist
func (f *FilterObserver) RemoveBlocklistEntry(protocol, ip string, port uint16) bool {
	key := ConnectionKey{
		Protocol: protocol,
		IP:       ip,
		Port:     port,
	}

	f.dynamicBlocklistMu.Lock()
	_, exists := f.dynamicBlocklist[key]
	if exists {
		delete(f.dynamicBlocklist, key)
	}
	f.dynamicBlocklistMu.Unlock()

	if exists {
		f.publishEvent("blocklist_updated", map[string]interface{}{
			"action":   "removed",
			"protocol": protocol,
			"ip":       ip,
			"port":     port,
		})
	}

	return exists
}

// RecordDNSResolution records IP→domain mappings from DNS A-record resolutions
func (f *FilterObserver) RecordDNSResolution(domain string, ips []string) {
	f.mu.Lock()
	for _, ip := range ips {
		f.dnsCache[ip] = domain
	}
	f.mu.Unlock()
}

// LookupDomain returns the domain name for an IP from the DNS cache
func (f *FilterObserver) LookupDomain(ip string) string {
	f.mu.RLock()
	domain := f.dnsCache[ip]
	f.mu.RUnlock()
	return domain
}

// lookupDomainLocked returns the domain name for an IP (caller must NOT hold f.mu exclusively,
// but may hold other locks). This acquires f.mu.RLock internally.
func (f *FilterObserver) lookupDomainLocked(ip string) string {
	f.mu.RLock()
	domain := f.dnsCache[ip]
	f.mu.RUnlock()
	return domain
}

// AddDomainBlocklistEntry blocks a domain and all its subdomains.
// For example, blocking "example.com" also blocks "www.example.com".
func (f *FilterObserver) AddDomainBlocklistEntry(domain, reason string) {
	compiled := regexp.MustCompile(`(^|\.)` + regexp.QuoteMeta(domain) + `$`)

	f.dynamicBlocklistMu.Lock()
	f.domainBlocklist[domain] = &DomainBlocklistEntry{
		Domain:   domain,
		compiled: compiled,
		AddedAt:  time.Now(),
		Reason:   reason,
	}
	f.dynamicBlocklistMu.Unlock()

	f.publishEvent("blocklist_updated", map[string]interface{}{
		"action": "added",
		"domain": domain,
		"reason": reason,
	})
}

// RemoveDomainBlocklistEntry removes a domain from the dynamic blocklist
func (f *FilterObserver) RemoveDomainBlocklistEntry(domain string) bool {
	f.dynamicBlocklistMu.Lock()
	_, exists := f.domainBlocklist[domain]
	if exists {
		delete(f.domainBlocklist, domain)
	}
	f.dynamicBlocklistMu.Unlock()

	if exists {
		f.publishEvent("blocklist_updated", map[string]interface{}{
			"action": "removed",
			"domain": domain,
		})
	}

	return exists
}

// GetDomainBlocklistEntries returns all domain blocklist entries
func (f *FilterObserver) GetDomainBlocklistEntries() []*DomainBlocklistEntry {
	f.dynamicBlocklistMu.RLock()
	defer f.dynamicBlocklistMu.RUnlock()

	var result []*DomainBlocklistEntry
	for _, entry := range f.domainBlocklist {
		result = append(result, entry)
	}
	return result
}

// ClearHistory clears all tracked connection and DNS history
func (f *FilterObserver) ClearHistory() (int, int) {
	f.mu.Lock()
	connectionCount := len(f.connections)
	dnsCount := len(f.dnsQueries)
	f.connections = make(map[ConnectionKey]*ConnectionRecord)
	f.dnsQueries = make(map[string]*DNSRecord)
	f.mu.Unlock()

	return connectionCount, dnsCount
}

// GetConnections returns all tracked connections
func (f *FilterObserver) GetConnections(statusFilter string) []*ConnectionRecord {
	f.mu.RLock()
	defer f.mu.RUnlock()

	var result []*ConnectionRecord
	for _, record := range f.connections {
		if statusFilter == "" || record.Status == statusFilter {
			result = append(result, record)
		}
	}
	return result
}

// GetDNSQueries returns all tracked DNS queries
func (f *FilterObserver) GetDNSQueries(statusFilter string) []*DNSRecord {
	f.mu.RLock()
	defer f.mu.RUnlock()

	var result []*DNSRecord
	for _, record := range f.dnsQueries {
		if statusFilter == "" || record.Status == statusFilter {
			result = append(result, record)
		}
	}
	return result
}

// GetAllowlistDomains returns all dynamic allowlist domain entries
func (f *FilterObserver) GetAllowlistDomains() []*DomainAllowlistEntry {
	f.dynamicAllowlistMu.RLock()
	defer f.dynamicAllowlistMu.RUnlock()

	var result []*DomainAllowlistEntry
	for _, entry := range f.dynamicAllowlist {
		result = append(result, entry)
	}
	return result
}

// GetConfigAllowlistPatterns returns all config-sourced allowlist pattern strings
func (f *FilterObserver) GetConfigAllowlistPatterns() []string {
	f.dynamicAllowlistMu.RLock()
	defer f.dynamicAllowlistMu.RUnlock()

	var result []string
	for pattern := range f.configAllowlist {
		result = append(result, pattern)
	}
	return result
}

// GetBlocklistEntries returns all blocklist entries
func (f *FilterObserver) GetBlocklistEntries() []*BlocklistEntry {
	f.dynamicBlocklistMu.RLock()
	defer f.dynamicBlocklistMu.RUnlock()

	var result []*BlocklistEntry
	for _, entry := range f.dynamicBlocklist {
		result = append(result, entry)
	}
	return result
}

// GetStats returns current statistics
func (f *FilterObserver) GetStats() map[string]interface{} {
	f.stats.RLock()
	defer f.stats.RUnlock()

	f.dynamicAllowlistMu.RLock()
	f.dynamicBlocklistMu.RLock()
	allowlistCount := len(f.configAllowlist) + len(f.dynamicAllowlist)
	blocklistCount := len(f.dynamicBlocklist) + len(f.domainBlocklist)
	f.dynamicBlocklistMu.RUnlock()
	f.dynamicAllowlistMu.RUnlock()

	return map[string]interface{}{
		"total_connections":   f.stats.TotalConnections,
		"blocked_connections": f.stats.BlockedConnections,
		"allowed_connections": f.stats.AllowedConnections,
		"total_dns_queries":   f.stats.TotalDNSQueries,
		"blocked_dns_queries": f.stats.BlockedDNSQueries,
		"uptime_seconds":      int64(time.Since(f.stats.StartTime).Seconds()),
		"allowlist_patterns":  allowlistCount,
		"blocklist_entries":   blocklistCount,
	}
}

// HasDynamicAllowlist reports whether any dynamic allowlist patterns are configured
func (f *FilterObserver) HasDynamicAllowlist() bool {
	f.dynamicAllowlistMu.RLock()
	defer f.dynamicAllowlistMu.RUnlock()
	return len(f.dynamicAllowlist) > 0
}

// evictOldestConnection removes the connection record with the oldest LastSeen.
// Caller must hold f.mu.
func (f *FilterObserver) evictOldestConnection() {
	var oldestKey ConnectionKey
	var oldestTime time.Time
	first := true
	for k, r := range f.connections {
		if first || r.LastSeen.Before(oldestTime) {
			oldestKey = k
			oldestTime = r.LastSeen
			first = false
		}
	}
	if !first {
		delete(f.connections, oldestKey)
	}
}

// evictOldestDNS removes the DNS record with the oldest LastSeen.
// Caller must hold f.mu.
func (f *FilterObserver) evictOldestDNS() {
	var oldestKey string
	var oldestTime time.Time
	first := true
	for k, r := range f.dnsQueries {
		if first || r.LastSeen.Before(oldestTime) {
			oldestKey = k
			oldestTime = r.LastSeen
			first = false
		}
	}
	if !first {
		delete(f.dnsQueries, oldestKey)
	}
}

// SetConfigAllowlist stores the config-sourced allowlist patterns
func (f *FilterObserver) SetConfigAllowlist(patterns []*regexp.Regexp) {
	f.dynamicAllowlistMu.Lock()
	defer f.dynamicAllowlistMu.Unlock()

	for _, compiled := range patterns {
		pattern := compiled.String()
		f.configAllowlist[pattern] = &ConfigAllowlistEntry{
			Pattern: pattern,
			AddedAt: time.Now(),
		}
	}
}
