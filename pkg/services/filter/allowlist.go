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
// on when static patterns are configured or once a dynamic allowlist entry has
// been added (see FilterObserver.AllowlistEnforced). Forwarders and the DNS
// server evaluate it for every request, so adding the first dynamic entry at
// runtime switches enforcement on. Removing the last dynamic entry does not
// switch it off (an empty allowlist then allows nothing); that takes an
// explicit FilterObserver.DisableDynamicAllowlistEnforcement.
func AllowlistActive(static []*regexp.Regexp, observer *FilterObserver) bool {
	return len(static) > 0 || (observer != nil && observer.AllowlistEnforced())
}

// DomainAllowed reports whether domain matches either the static allowlist
// patterns or the observer's dynamic allowlist.
func DomainAllowed(domain string, static []*regexp.Regexp, observer *FilterObserver) bool {
	if MatchesOutboundAllowlist(domain, static) {
		return true
	}
	return observer != nil && observer.MatchesDynamicAllowlist(domain)
}
