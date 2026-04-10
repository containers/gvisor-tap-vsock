package dns

import (
	"strings"
	"sync"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/services/forwarder"
	"github.com/containers/gvisor-tap-vsock/pkg/types"
	log "github.com/sirupsen/logrus"
)

// DeniedDomain represents a recently denied DNS query.
type DeniedDomain struct {
	Domain    string `json:"domain"`
	Count     int    `json:"count"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
}

// DNSFilter checks whether a DNS query for a domain should be resolved upstream.
// It tracks denied domains and supports dynamic allow-list updates at runtime.
type DNSFilter struct {
	mu             sync.RWMutex
	defaultDeny    bool
	allowedDomains []string
	blockedDomains []string
	// dynamicAllowed are domains added at runtime via the HTTP API
	dynamicAllowed []string
	// denied tracks recently denied domains for the pending API
	denied map[string]*DeniedDomain
	// networkFilter is used to publish SSE events
	networkFilter *forwarder.SharedFilter
}

// NewDNSFilter creates a DNS filter from a DNSPolicy. Returns nil if policy is nil.
func NewDNSFilter(policy *types.DNSPolicy) *DNSFilter {
	if policy == nil {
		return nil
	}
	return &DNSFilter{
		defaultDeny:    policy.DefaultAction == "deny",
		allowedDomains: policy.AllowedDomains,
		blockedDomains: policy.BlockedDomains,
		denied:         make(map[string]*DeniedDomain),
	}
}

// SetNetworkFilter sets the shared network filter for publishing SSE events.
func (f *DNSFilter) SetNetworkFilter(nf *forwarder.SharedFilter) {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.networkFilter = nf
}

// Allow checks whether upstream resolution for the given domain is permitted.
// The domain should be in DNS wire format (trailing dot), e.g. "example.com."
func (f *DNSFilter) Allow(domain string) bool {
	if f == nil {
		return true
	}

	// Normalize: remove trailing dot, lowercase
	name := strings.TrimSuffix(strings.ToLower(domain), ".")

	f.mu.RLock()
	blocked := f.blockedDomains
	allowed := f.allowedDomains
	dynamic := f.dynamicAllowed
	defaultDeny := f.defaultDeny
	f.mu.RUnlock()

	// Check blocked list first (explicit blocks always win)
	for _, pattern := range blocked {
		if matchDomain(name, strings.ToLower(pattern)) {
			log.Infof("dns policy: DENY resolution of %q (matched blocked pattern %q)", name, pattern)
			f.trackDenied(name)
			return false
		}
	}

	// Check static allowed list
	for _, pattern := range allowed {
		if matchDomain(name, strings.ToLower(pattern)) {
			log.Debugf("dns policy: ALLOW resolution of %q (matched allowed pattern %q)", name, pattern)
			return true
		}
	}

	// Check dynamic allowed list (added at runtime via API)
	for _, pattern := range dynamic {
		if matchDomain(name, strings.ToLower(pattern)) {
			log.Infof("dns policy: ALLOW resolution of %q (matched dynamic pattern %q)", name, pattern)
			return true
		}
	}

	if defaultDeny {
		log.Infof("dns policy: DENY resolution of %q (default deny)", name)
		f.trackDenied(name)
		return false
	}
	return true
}

func (f *DNSFilter) trackDenied(name string) {
	f.mu.Lock()
	now := time.Now().UTC().Format(time.RFC3339)
	var d *DeniedDomain
	if existing, ok := f.denied[name]; ok {
		existing.Count++
		existing.LastSeen = now
		d = existing
	} else {
		d = &DeniedDomain{
			Domain:    name,
			Count:     1,
			FirstSeen: now,
			LastSeen:  now,
		}
		f.denied[name] = d
	}
	nf := f.networkFilter
	f.mu.Unlock()
	if nf != nil {
		nf.PublishDNSEvent("dns_denied", *d)
	}
}

// DeniedDomains returns a snapshot of all recently denied domains.
func (f *DNSFilter) DeniedDomains() []DeniedDomain {
	if f == nil {
		return nil
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	result := make([]DeniedDomain, 0, len(f.denied))
	for _, d := range f.denied {
		result = append(result, *d)
	}
	return result
}

// AddAllowed adds a domain pattern to the dynamic allow list.
// Supports exact match ("example.com") and wildcards ("*.example.com").
// Returns true if the domain was previously denied (and is now cleared from denied list).
func (f *DNSFilter) AddAllowed(pattern string) bool {
	if f == nil {
		return false
	}
	pattern = strings.TrimSuffix(strings.ToLower(pattern), ".")
	f.mu.Lock()
	f.dynamicAllowed = append(f.dynamicAllowed, pattern)

	// Clear matching entries from denied list
	wasDenied := false
	for name := range f.denied {
		if matchDomain(name, pattern) {
			delete(f.denied, name)
			wasDenied = true
		}
	}
	nf := f.networkFilter
	f.mu.Unlock()
	log.Infof("dns policy: added dynamic allow pattern %q", pattern)
	if nf != nil {
		nf.PublishDNSEvent("dns_allowed", map[string]string{"domain": pattern})
	}
	return wasDenied
}

// DynamicAllowed returns the list of dynamically added allow patterns.
func (f *DNSFilter) DynamicAllowed() []string {
	if f == nil {
		return nil
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	result := make([]string, len(f.dynamicAllowed))
	copy(result, f.dynamicAllowed)
	return result
}

// matchDomain checks if name matches pattern.
// Supports:
//   - exact match: "example.com" matches "example.com"
//   - wildcard prefix: "*.example.com" matches "foo.example.com" and "bar.baz.example.com"
//   - bare wildcard with dot: "*.com" matches "example.com"
func matchDomain(name, pattern string) bool {
	if name == pattern {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // keep the dot: ".example.com"
		return strings.HasSuffix(name, suffix)
	}
	return false
}
