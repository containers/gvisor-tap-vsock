package filter

import "regexp"

// MatchesOutboundAllowlist reports whether domain matches any compiled pattern in allowlist.
// An empty allowlist matches nothing (returns false).
func MatchesOutboundAllowlist(domain string, allowlist []*regexp.Regexp) bool {
	for _, re := range allowlist {
		if re.MatchString(domain) {
			return true
		}
	}
	return false
}

// AllowlistActive reports whether outbound allowlist enforcement is on. It is
// on when static patterns are configured or when the observer's dynamic
// allowlist has at least one entry. Forwarders and the DNS server evaluate it
// for every request, so adding the first dynamic entry at runtime switches
// enforcement on and removing the last one (with no static patterns) switches
// it off again.
func AllowlistActive(static []*regexp.Regexp, observer *FilterObserver) bool {
	return len(static) > 0 || (observer != nil && observer.HasDynamicAllowlist())
}

// DomainAllowed reports whether domain matches either the static allowlist
// patterns or the observer's dynamic allowlist.
func DomainAllowed(domain string, static []*regexp.Regexp, observer *FilterObserver) bool {
	if MatchesOutboundAllowlist(domain, static) {
		return true
	}
	return observer != nil && observer.MatchesDynamicAllowlist(domain)
}
