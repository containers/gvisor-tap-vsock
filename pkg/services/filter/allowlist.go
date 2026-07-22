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
