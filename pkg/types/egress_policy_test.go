package types

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEgressPolicyAllowlist(t *testing.T) {
	policy := &EgressPolicy{Revision: "r1", Allow: []EgressRule{{
		Protocol: "tcp",
		CIDR:     "127.0.0.1/32",
		Port:     39489,
	}}}
	holder, err := NewEgressPolicyHolder(policy, true)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	tests := []struct {
		name     string
		protocol string
		address  string
		port     uint16
		want     bool
	}{
		{"exact tuple allowed", "tcp", "127.0.0.1", 39489, true},
		{"wrong port denied", "tcp", "127.0.0.1", 39490, false},
		{"wrong protocol denied", "udp", "127.0.0.1", 39489, false},
		{"wrong address denied", "tcp", "192.0.2.10", 39489, false},
		{"invalid address denied", "tcp", "not-an-ip", 39489, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := holder.Allows(tt.protocol, tt.address, tt.port); got != tt.want {
				t.Fatalf("Allows(%q, %q, %d) = %v, want %v", tt.protocol, tt.address, tt.port, got, tt.want)
			}
		})
	}
}

func TestNilEgressPolicyRetainsLegacyForwarding(t *testing.T) {
	holder, err := NewEgressPolicyHolder(nil, false)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	if holder.Enabled() {
		t.Fatal("nil policy must not be enabled")
	}
	if !holder.Allows("tcp", "203.0.113.1", 443) {
		t.Fatal("nil policy must preserve upstream default forwarding")
	}
}

func TestRequiredEgressPolicyFailsClosed(t *testing.T) {
	if _, err := NewEgressPolicyHolder(nil, true); err == nil {
		t.Fatal("required policy with nil configuration must fail")
	}
}

func TestEmptyEgressPolicyDeniesByDefault(t *testing.T) {
	holder, err := NewEgressPolicyHolder(&EgressPolicy{Revision: "empty"}, true)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	if holder.Allows("tcp", "127.0.0.1", 443) || holder.Allows("udp", "127.0.0.1", 53) {
		t.Fatal("a present policy with no allow rules must deny by default")
	}
}

func TestInvalidCIDRDoesNotAllow(t *testing.T) {
	policy := &EgressPolicy{Allow: []EgressRule{{Protocol: "tcp", CIDR: "invalid", Port: 443}}}
	if err := policy.Validate(); err == nil {
		t.Fatal("invalid CIDR must be rejected at validation time")
	}
}

func TestEmptyProtocolIsRejected(t *testing.T) {
	policy := &EgressPolicy{Allow: []EgressRule{{CIDR: "127.0.0.1/32", Port: 443}}}
	if err := policy.Validate(); err == nil {
		t.Fatal("empty protocol must not be an implicit wildcard")
	}
}

func TestEmptyCIDRNeedsExplicitAllowAny(t *testing.T) {
	policy := &EgressPolicy{Allow: []EgressRule{{Protocol: "tcp", Port: 443}}}
	if err := policy.Validate(); err == nil {
		t.Fatal("empty CIDR without allowAny must be rejected")
	}
	policy.AllowAny = true
	if err := policy.Validate(); err != nil {
		t.Fatalf("empty CIDR with allowAny should be accepted: %v", err)
	}
	holder, err := NewEgressPolicyHolder(policy, true)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	if !holder.Allows("tcp", "203.0.113.1", 443) {
		t.Fatal("explicit allowAny rule should allow any address on its port")
	}
	if holder.Allows("tcp", "203.0.113.1", 444) {
		t.Fatal("explicit allowAny rule must still honor the port")
	}
}

func TestDenyTakesPrecedence(t *testing.T) {
	policy := &EgressPolicy{
		Revision: "r2",
		Allow:    []EgressRule{{Protocol: "tcp", CIDR: "10.0.0.0/8"}},
		Deny:     []EgressRule{{Protocol: "tcp", CIDR: "10.1.0.0/16"}},
	}
	holder, err := NewEgressPolicyHolder(policy, true)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	if !holder.Allows("tcp", "10.2.0.1", 443) {
		t.Fatal("allowed CIDR should be allowed")
	}
	if holder.Allows("tcp", "10.1.2.3", 443) {
		t.Fatal("deny must take precedence over allow")
	}
}

func TestAuditRecordContainsRevisionAndRule(t *testing.T) {
	path := filepath.Join(t.TempDir(), "egress.jsonl")
	holder, err := NewEgressPolicyHolder(&EgressPolicy{
		Revision:  "r3",
		SandboxID: "sbx-test",
		AuditLog:  path,
		Allow:     []EgressRule{{Protocol: "tcp", CIDR: "127.0.0.1/32", Port: 39489}},
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if !holder.Allows("tcp", "127.0.0.1", 39489) {
		t.Fatal("expected allow")
	}
	if holder.Allows("tcp", "127.0.0.1", 39490) {
		t.Fatal("expected deny")
	}
	if err := holder.Close(); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(content) == 0 {
		t.Fatal("audit log is empty")
	}
	for _, want := range []string{`"revision":"r3"`, `"sandboxId":"sbx-test"`, `"action":"allow"`, `"action":"deny"`, `"rule":"default-deny"`} {
		if !strings.Contains(string(content), want) {
			t.Fatalf("audit log does not contain %s: %s", want, content)
		}
	}
}

type fakeCloser struct {
	closed bool
}

func (f *fakeCloser) Close() error {
	f.closed = true
	return nil
}

func TestTrackedFlowIsClosedOnRevocation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "egress.jsonl")
	holder, err := NewEgressPolicyHolder(&EgressPolicy{
		Revision: "r1",
		AuditLog: path,
		Allow:    []EgressRule{{Protocol: "tcp", CIDR: "127.0.0.1/32", Port: 39489}},
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	flow := &fakeCloser{}
	id := holder.Track("tcp", "127.0.0.1", 39489, flow)
	if id == 0 {
		t.Fatal("allowed flow was not tracked")
	}
	if err := holder.Update(&EgressPolicy{
		Revision: "r2",
		AuditLog: path,
		Deny:     []EgressRule{{Protocol: "tcp", CIDR: "127.0.0.1/32", Port: 39489}},
	}); err != nil {
		t.Fatal(err)
	}
	if !flow.closed {
		t.Fatal("established flow was not closed after revocation")
	}
	holder.Untrack(id)
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), `"rule":"revoke:deny:tcp 127.0.0.1/32 port=39489"`) {
		t.Fatalf("audit does not contain revocation record: %s", content)
	}
}

func TestTrackDeniedFlowReturnsZero(t *testing.T) {
	holder, err := NewEgressPolicyHolder(&EgressPolicy{
		Revision: "r1",
		Allow:    []EgressRule{{Protocol: "tcp", CIDR: "127.0.0.1/32", Port: 39489}},
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	flow := &fakeCloser{}
	if id := holder.Track("tcp", "127.0.0.1", 39490, flow); id != 0 {
		t.Fatal("denied flow must not be tracked")
	}
	if flow.closed {
		t.Fatal("Track must not close a flow it never owned")
	}
}

func TestPolicyUpdateSwapsRevision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "egress.jsonl")
	holder, err := NewEgressPolicyHolder(&EgressPolicy{
		Revision: "r1",
		AuditLog: path,
		Allow:    []EgressRule{{Protocol: "tcp", CIDR: "127.0.0.1/32", Port: 39489}},
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	if !holder.Allows("tcp", "127.0.0.1", 39489) {
		t.Fatal("initial policy should allow port 39489")
	}
	if err := holder.Update(&EgressPolicy{
		Revision: "r2",
		AuditLog: path,
		Allow:    []EgressRule{{Protocol: "tcp", CIDR: "127.0.0.1/32", Port: 39490}},
	}); err != nil {
		t.Fatal(err)
	}
	if holder.Revision() != "r2" {
		t.Fatalf("revision = %q, want r2", holder.Revision())
	}
	if holder.Allows("tcp", "127.0.0.1", 39489) {
		t.Fatal("old rule must not survive update")
	}
	if !holder.Allows("tcp", "127.0.0.1", 39490) {
		t.Fatal("new rule should allow port 39490")
	}
	if err := holder.Update(nil); err == nil {
		t.Fatal("required holder must refuse removal")
	}
}

func TestDomainPolicyRequiresDNSBinding(t *testing.T) {
	holder, err := NewEgressPolicyHolder(&EgressPolicy{
		Revision: "domains",
		Allow: []EgressRule{
			{Protocol: "tcp", Domain: "*.example.com", Port: 443},
			{Protocol: "tcp", Domain: "**.internal.example", Port: 8443},
			{Protocol: "tcp", Domain: "api[12].example.net", Port: 443},
		},
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if holder.Allows("tcp", "203.0.113.10", 443) {
		t.Fatal("domain rule allowed an address before DNS")
	}
	if !holder.DNSAllowed("api.example.com") || !holder.DNSAllowed("a.b.internal.example") {
		t.Fatal("allowed domain was refused DNS")
	}
	if holder.DNSAllowed("api.example.org") || holder.DNSAllowed("example.com") {
		t.Fatal("non-matching domain was allowed DNS")
	}
	holder.RecordDNS("api.example.com", []net.IPAddr{{IP: net.ParseIP("203.0.113.10")}})
	if !holder.Allows("tcp", "203.0.113.10", 443) {
		t.Fatal("resolved domain address was denied")
	}
	if holder.Allows("tcp", "203.0.113.10", 80) {
		t.Fatal("port mismatch was allowed")
	}
	holder.RecordDNS("other.example.org", []net.IPAddr{{IP: net.ParseIP("203.0.113.11")}})
	if holder.Allows("tcp", "203.0.113.11", 443) {
		t.Fatal("unauthorized DNS answer was recorded")
	}
}

func TestDomainDenyWins(t *testing.T) {
	holder, err := NewEgressPolicyHolder(&EgressPolicy{
		Revision: "deny",
		Allow:    []EgressRule{{Protocol: "tcp", Domain: "**.example.com", Port: 443}},
		Deny:     []EgressRule{{Protocol: "tcp", Domain: "secret.example.com", Port: 443}},
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if holder.DNSAllowed("secret.example.com") {
		t.Fatal("denied domain allowed DNS")
	}
	holder.RecordDNS("secret.example.com", []net.IPAddr{{IP: net.ParseIP("203.0.113.12")}})
	if holder.Allows("tcp", "203.0.113.12", 443) {
		t.Fatal("denied domain allowed traffic")
	}
}

func TestDomainRuleNeedsDomainOrCIDR(t *testing.T) {
	for _, rule := range []EgressRule{
		{Protocol: "tcp", CIDR: "192.0.2.0/24", Domain: "example.com"},
		{Protocol: "tcp", Domain: "*"},
		{Protocol: "tcp", Domain: "api.*.example.com"},
	} {
		if _, err := NewEgressPolicyHolder(&EgressPolicy{Allow: []EgressRule{rule}}, true); err == nil {
			t.Fatalf("rule %+v accepted", rule)
		}
	}
}
