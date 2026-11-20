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

	// Removing the last dynamic entry must not open all outbound traffic.
	obs.RemoveAllowlistDomain("github.com")
	require.True(t, AllowlistActive(nil, obs), "enforcement must stay on after the last entry is removed")
	require.False(t, DomainAllowed("github.com", nil, obs), "an empty allowlist allows nothing")

	// Config patterns registered on the observer also count as enforcement.
	withConfig := NewFilterObserver(0)
	withConfig.SetConfigAllowlist(static)
	require.True(t, withConfig.AllowlistEnforced())
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

func TestDisableDynamicAllowlistEnforcement(t *testing.T) {
	obs := NewFilterObserver(0)
	require.NoError(t, obs.DisableDynamicAllowlistEnforcement(), "disabling when already off is a no-op")

	obs.AddAllowlistDomain("github.com")
	require.ErrorIs(t, obs.DisableDynamicAllowlistEnforcement(), ErrAllowlistEntriesRemain)
	require.True(t, AllowlistActive(nil, obs), "a refused disable must leave enforcement on")

	obs.RemoveAllowlistDomain("github.com")
	require.True(t, AllowlistActive(nil, obs), "removing the last entry alone keeps enforcement on")

	require.NoError(t, obs.DisableDynamicAllowlistEnforcement())
	require.False(t, AllowlistActive(nil, obs), "explicit disable turns enforcement off")

	// Adding an entry again re-enables enforcement.
	obs.AddAllowlistDomain("github.com")
	require.True(t, AllowlistActive(nil, obs))
}

func TestDisableDynamicAllowlistEnforcement_ConfigPatterns(t *testing.T) {
	obs := NewFilterObserver(0)
	obs.SetConfigAllowlist([]*regexp.Regexp{regexp.MustCompile(`^example\.com$`)})
	require.ErrorIs(t, obs.DisableDynamicAllowlistEnforcement(), ErrAllowlistEnforcedByConfig)
	require.True(t, obs.AllowlistEnforced())
}
