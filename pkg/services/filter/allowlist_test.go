package filter

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMatchesOutboundAllowlist_Empty(t *testing.T) {
	require.False(t, MatchesOutboundAllowlist("anything", nil))
	require.False(t, MatchesOutboundAllowlist("anything", []*regexp.Regexp{}))
}

func TestMatchesOutboundAllowlist_Match(t *testing.T) {
	re := regexp.MustCompile(`^example\.com$`)
	require.True(t, MatchesOutboundAllowlist("example.com", []*regexp.Regexp{re}))
	require.False(t, MatchesOutboundAllowlist("other.com", []*regexp.Regexp{re}))
}

func TestAllowlistActive(t *testing.T) {
	static := []*regexp.Regexp{regexp.MustCompile(`^example\.com$`)}

	require.False(t, AllowlistActive(nil, nil))
	require.True(t, AllowlistActive(static, nil))

	obs := NewFilterObserver(0)
	require.False(t, AllowlistActive(nil, obs))
	require.True(t, AllowlistActive(static, obs))

	obs.AddAllowlistDomain("github.com")
	require.True(t, AllowlistActive(nil, obs), "a dynamic entry alone must turn enforcement on")

	obs.RemoveAllowlistDomain("github.com")
	require.False(t, AllowlistActive(nil, obs))
}

func TestDomainAllowed(t *testing.T) {
	static := []*regexp.Regexp{regexp.MustCompile(`^example\.com$`)}
	obs := NewFilterObserver(0)
	obs.AddAllowlistDomain("github.com")

	require.True(t, DomainAllowed("example.com", static, obs), "static match")
	require.True(t, DomainAllowed("api.github.com", static, obs), "dynamic match")
	require.False(t, DomainAllowed("evil.com", static, obs))

	require.True(t, DomainAllowed("github.com", nil, obs), "dynamic only")
	require.False(t, DomainAllowed("example.com", nil, obs))
	require.True(t, DomainAllowed("example.com", static, nil), "nil observer")
	require.False(t, DomainAllowed("github.com", static, nil))
}
