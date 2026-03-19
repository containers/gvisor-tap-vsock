package dns

import (
	"testing"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
)

func TestNilDNSFilterAllows(t *testing.T) {
	var f *DNSFilter
	if !f.Allow("example.com.") {
		t.Fatal("nil filter should allow everything")
	}
}

func TestDNSDefaultDeny(t *testing.T) {
	f := NewDNSFilter(&types.DNSPolicy{
		DefaultAction: "deny",
	})
	if f.Allow("example.com.") {
		t.Fatal("default deny should block")
	}
}

func TestDNSDefaultAllow(t *testing.T) {
	f := NewDNSFilter(&types.DNSPolicy{
		DefaultAction: "allow",
	})
	if !f.Allow("example.com.") {
		t.Fatal("default allow should permit")
	}
}

func TestDNSAllowedDomains(t *testing.T) {
	f := NewDNSFilter(&types.DNSPolicy{
		DefaultAction:  "deny",
		AllowedDomains: []string{"*.github.com", "example.com"},
	})

	tests := []struct {
		domain   string
		expected bool
	}{
		{"api.github.com.", true},
		{"raw.github.com.", true},
		{"github.com.", false}, // wildcard *.github.com doesn't match github.com itself
		{"example.com.", true},
		{"evil.com.", false},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := f.Allow(tt.domain)
			if got != tt.expected {
				t.Errorf("Allow(%q) = %v, want %v", tt.domain, got, tt.expected)
			}
		})
	}
}

func TestDNSBlockedDomains(t *testing.T) {
	f := NewDNSFilter(&types.DNSPolicy{
		DefaultAction:  "allow",
		BlockedDomains: []string{"*.evil.com", "malware.org"},
	})

	tests := []struct {
		domain   string
		expected bool
	}{
		{"foo.evil.com.", false},
		{"malware.org.", false},
		{"example.com.", true},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := f.Allow(tt.domain)
			if got != tt.expected {
				t.Errorf("Allow(%q) = %v, want %v", tt.domain, got, tt.expected)
			}
		})
	}
}

func TestDNSBlockedOverridesAllowed(t *testing.T) {
	f := NewDNSFilter(&types.DNSPolicy{
		DefaultAction:  "deny",
		AllowedDomains: []string{"*.example.com"},
		BlockedDomains: []string{"secret.example.com"},
	})

	if f.Allow("secret.example.com.") {
		t.Error("blocked should override allowed")
	}
	if !f.Allow("public.example.com.") {
		t.Error("non-blocked subdomain should be allowed")
	}
}

func TestDNSCaseInsensitive(t *testing.T) {
	f := NewDNSFilter(&types.DNSPolicy{
		DefaultAction:  "deny",
		AllowedDomains: []string{"*.GitHub.COM"},
	})

	if !f.Allow("API.GITHUB.COM.") {
		t.Error("matching should be case-insensitive")
	}
}

func TestDNSDeniedTracking(t *testing.T) {
	f := NewDNSFilter(&types.DNSPolicy{
		DefaultAction: "deny",
	})

	f.Allow("example.com.")
	f.Allow("example.com.")
	f.Allow("other.com.")

	denied := f.DeniedDomains()
	if len(denied) != 2 {
		t.Fatalf("expected 2 denied domains, got %d", len(denied))
	}

	found := false
	for _, d := range denied {
		if d.Domain == "example.com" {
			found = true
			if d.Count != 2 {
				t.Errorf("example.com count = %d, want 2", d.Count)
			}
		}
	}
	if !found {
		t.Error("example.com not found in denied list")
	}
}

func TestDNSDynamicAllow(t *testing.T) {
	f := NewDNSFilter(&types.DNSPolicy{
		DefaultAction: "deny",
	})

	// First denied
	if f.Allow("www.google.com.") {
		t.Error("should be denied initially")
	}
	if len(f.DeniedDomains()) != 1 {
		t.Error("should have 1 denied domain")
	}

	// Add dynamic allow
	wasDenied := f.AddAllowed("*.google.com")
	if !wasDenied {
		t.Error("AddAllowed should report it was previously denied")
	}

	// Now allowed
	if !f.Allow("www.google.com.") {
		t.Error("should be allowed after dynamic add")
	}

	// Denied list should be cleared for this domain
	if len(f.DeniedDomains()) != 0 {
		t.Error("denied list should be cleared after allowing")
	}

	// Check DynamicAllowed
	allowed := f.DynamicAllowed()
	if len(allowed) != 1 || allowed[0] != "*.google.com" {
		t.Errorf("DynamicAllowed = %v, want [*.google.com]", allowed)
	}
}

func TestDNSDynamicAllowExact(t *testing.T) {
	f := NewDNSFilter(&types.DNSPolicy{
		DefaultAction: "deny",
	})

	f.AddAllowed("www.google.fr")

	if !f.Allow("www.google.fr.") {
		t.Error("exact domain should be allowed")
	}
	if f.Allow("mail.google.fr.") {
		t.Error("other subdomains should still be denied")
	}
}

func TestNilDNSFilterMethods(t *testing.T) {
	var f *DNSFilter
	if f.DeniedDomains() != nil {
		t.Error("nil filter DeniedDomains should return nil")
	}
	if f.DynamicAllowed() != nil {
		t.Error("nil filter DynamicAllowed should return nil")
	}
	if f.AddAllowed("example.com") {
		t.Error("nil filter AddAllowed should return false")
	}
}
