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
