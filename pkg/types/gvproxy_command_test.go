package types

import (
	"slices"
	"testing"
)

func TestGvproxyCommandEnableIPv6(t *testing.T) {
	t.Run("omits -enable-ipv6 by default", func(t *testing.T) {
		cmd := NewGvproxyCommand()
		if slices.Contains(cmd.ToCmdline(), "-enable-ipv6") {
			t.Fatalf("expected -enable-ipv6 to be absent by default, got %v", cmd.ToCmdline())
		}
	})

	t.Run("emits -enable-ipv6 when enabled", func(t *testing.T) {
		cmd := NewGvproxyCommand()
		cmd.EnableIPv6 = true
		if !slices.Contains(cmd.ToCmdline(), "-enable-ipv6") {
			t.Fatalf("expected -enable-ipv6 to be present, got %v", cmd.ToCmdline())
		}
	})
}
