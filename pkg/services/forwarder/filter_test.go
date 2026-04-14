package forwarder

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
)

func TestNilFilterAllowsEverything(t *testing.T) {
	var f *NetworkFilter
	if !f.Allow("tcp", net.ParseIP("8.8.8.8"), 443) {
		t.Fatal("nil filter should allow everything")
	}
}

func TestNilPolicyReturnsNilFilter(t *testing.T) {
	f := NewNetworkFilter(nil)
	if f != nil {
		t.Fatal("nil policy should produce nil filter")
	}
}

func TestDefaultAllow(t *testing.T) {
	f := NewNetworkFilter(&types.NetworkPolicy{
		DefaultAction: "allow",
	})
	if !f.Allow("tcp", net.ParseIP("1.2.3.4"), 80) {
		t.Fatal("default allow should permit traffic")
	}
}

func TestDefaultDeny(t *testing.T) {
	f := NewNetworkFilter(&types.NetworkPolicy{
		DefaultAction: "deny",
	})
	if f.Allow("tcp", net.ParseIP("1.2.3.4"), 80) {
		t.Fatal("default deny should block traffic")
	}
}

func TestDenyWithAllowRules(t *testing.T) {
	f := NewNetworkFilter(&types.NetworkPolicy{
		DefaultAction: "deny",
		Rules: []types.NetworkRule{
			{Action: "allow", CIDR: "0.0.0.0/0", Ports: []int{80, 443}},
		},
	})

	tests := []struct {
		name     string
		proto    string
		ip       string
		port     int
		expected bool
	}{
		{"allow http", "tcp", "93.184.216.34", 80, true},
		{"allow https", "tcp", "93.184.216.34", 443, true},
		{"deny ssh", "tcp", "93.184.216.34", 22, false},
		{"deny arbitrary port", "tcp", "10.0.0.1", 8080, false},
		{"allow udp 443", "udp", "1.1.1.1", 443, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := f.Allow(tt.proto, net.ParseIP(tt.ip), tt.port)
			if got != tt.expected {
				t.Errorf("Allow(%s, %s, %d) = %v, want %v", tt.proto, tt.ip, tt.port, got, tt.expected)
			}
		})
	}
}

func TestAllowWithDenyRules(t *testing.T) {
	f := NewNetworkFilter(&types.NetworkPolicy{
		DefaultAction: "allow",
		Rules: []types.NetworkRule{
			{Action: "deny", CIDR: "10.0.0.0/8"},
			{Action: "deny", CIDR: "172.16.0.0/12"},
		},
	})

	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{"deny private 10.x", "10.1.2.3", false},
		{"deny private 172.x", "172.20.0.1", false},
		{"allow public", "8.8.8.8", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := f.Allow("tcp", net.ParseIP(tt.ip), 80)
			if got != tt.expected {
				t.Errorf("Allow(tcp, %s, 80) = %v, want %v", tt.ip, got, tt.expected)
			}
		})
	}
}

func TestProtocolFiltering(t *testing.T) {
	f := NewNetworkFilter(&types.NetworkPolicy{
		DefaultAction: "deny",
		Rules: []types.NetworkRule{
			{Action: "allow", Protocol: "tcp", Ports: []int{443}},
		},
	})

	if !f.Allow("tcp", net.ParseIP("1.1.1.1"), 443) {
		t.Error("should allow TCP 443")
	}
	if f.Allow("udp", net.ParseIP("1.1.1.1"), 443) {
		t.Error("should deny UDP 443 (rule is TCP-only)")
	}
}

func TestFirstMatchWins(t *testing.T) {
	f := NewNetworkFilter(&types.NetworkPolicy{
		DefaultAction: "allow",
		Rules: []types.NetworkRule{
			{Action: "deny", CIDR: "10.0.0.0/8"},
			{Action: "allow", CIDR: "10.0.0.1/32"},
		},
	})

	// First rule matches, so 10.0.0.1 should be denied even though second rule allows it
	if f.Allow("tcp", net.ParseIP("10.0.0.1"), 80) {
		t.Error("first matching rule should win (deny)")
	}
}

func TestAllowAddr(t *testing.T) {
	f := NewNetworkFilter(&types.NetworkPolicy{
		DefaultAction: "deny",
		Rules: []types.NetworkRule{
			{Action: "allow", Ports: []int{443}},
		},
	})

	sf := NewSharedFilter(&types.NetworkPolicy{
		DefaultAction: "deny",
		Rules: []types.NetworkRule{
			{Action: "allow", Ports: []int{443}},
		},
	})
	_ = f // original filter tested via SharedFilter
	if !sf.AllowAddr("tcp", "1.2.3.4:443") {
		t.Error("should allow 1.2.3.4:443")
	}
	if sf.AllowAddr("tcp", "1.2.3.4:80") {
		t.Error("should deny 1.2.3.4:80")
	}
}

func TestInvalidCIDRSkipped(t *testing.T) {
	f := NewNetworkFilter(&types.NetworkPolicy{
		DefaultAction: "deny",
		Rules: []types.NetworkRule{
			{Action: "allow", CIDR: "not-a-cidr"},
			{Action: "allow", Ports: []int{80}},
		},
	})

	// Invalid CIDR rule is skipped, second rule should match
	if !f.Allow("tcp", net.ParseIP("1.1.1.1"), 80) {
		t.Error("invalid CIDR should be skipped, next rule should match")
	}
}

func TestSharedFilterUpdate(t *testing.T) {
	sf := NewSharedFilter(nil)
	if !sf.Allow("tcp", net.ParseIP("1.1.1.1"), 80) {
		t.Error("nil policy should allow")
	}

	sf.Update(&types.NetworkPolicy{DefaultAction: "deny"})
	if sf.Allow("tcp", net.ParseIP("1.1.1.1"), 80) {
		t.Error("updated deny policy should block")
	}
}

func TestInteractiveApproval(t *testing.T) {
	sf := NewSharedFilter(&types.NetworkPolicy{
		DefaultAction:  "deny",
		Interactive:     true,
		ApprovalTimeout: 2,
	})

	ip := net.ParseIP("93.184.216.34")

	// Approve in a goroutine shortly after the request is made
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Wait for the request to appear as pending
		for i := 0; i < 50; i++ {
			pending := sf.PendingRequests()
			if len(pending) > 0 {
				sf.Approve("tcp", "93.184.216.34", 443)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Error("pending request never appeared")
	}()

	// This blocks until approved
	result := sf.Allow("tcp", ip, 443)
	wg.Wait()

	if !result {
		t.Error("connection should be allowed after interactive approval")
	}

	// Subsequent calls should be fast (cached)
	if !sf.Allow("tcp", ip, 443) {
		t.Error("cached approval should allow")
	}
}

func TestInteractiveDeny(t *testing.T) {
	sf := NewSharedFilter(&types.NetworkPolicy{
		DefaultAction:  "deny",
		Interactive:     true,
		ApprovalTimeout: 2,
	})

	ip := net.ParseIP("10.0.0.1")

	go func() {
		for i := 0; i < 50; i++ {
			if len(sf.PendingRequests()) > 0 {
				sf.Deny("tcp", "10.0.0.1", 22)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	result := sf.Allow("tcp", ip, 22)
	if result {
		t.Error("connection should be denied after interactive denial")
	}

	// Cached denial
	if sf.Allow("tcp", ip, 22) {
		t.Error("cached denial should deny")
	}
}

func TestInteractiveTimeout(t *testing.T) {
	sf := NewSharedFilter(&types.NetworkPolicy{
		DefaultAction:  "deny",
		Interactive:     true,
		ApprovalTimeout: 1, // 1 second timeout
	})

	start := time.Now()
	result := sf.Allow("tcp", net.ParseIP("1.2.3.4"), 80)
	elapsed := time.Since(start)

	if result {
		t.Error("should deny on timeout")
	}
	if elapsed < 900*time.Millisecond {
		t.Errorf("should have waited ~1s, waited %v", elapsed)
	}
}

func TestInteractiveNotification(t *testing.T) {
	sf := NewSharedFilter(&types.NetworkPolicy{
		DefaultAction:  "deny",
		Interactive:     true,
		ApprovalTimeout: 2,
	})

	var received []types.NotificationMessage
	var mu sync.Mutex
	sf.SetNotifyFunc(func(msg types.NotificationMessage) {
		mu.Lock()
		received = append(received, msg)
		mu.Unlock()
	})

	go func() {
		for i := 0; i < 50; i++ {
			if len(sf.PendingRequests()) > 0 {
				sf.Approve("tcp", "8.8.8.8", 53)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	sf.Allow("tcp", net.ParseIP("8.8.8.8"), 53)

	mu.Lock()
	defer mu.Unlock()
	if len(received) == 0 {
		t.Error("should have received a notification")
	}
	if received[0].NotificationType != types.NetworkPolicyPending {
		t.Errorf("notification type = %q, want %q", received[0].NotificationType, types.NetworkPolicyPending)
	}
	if received[0].Details["ip"] != "8.8.8.8" {
		t.Errorf("notification ip = %q, want 8.8.8.8", received[0].Details["ip"])
	}
}

func TestApprovedList(t *testing.T) {
	sf := NewSharedFilter(&types.NetworkPolicy{
		DefaultAction:  "deny",
		Interactive:     true,
		ApprovalTimeout: 2,
	})

	sf.Approve("tcp", "1.2.3.4", 443)
	sf.Deny("tcp", "10.0.0.1", 22)

	approved := sf.ApprovedList()
	if !approved["tcp:1.2.3.4:443"] {
		t.Error("should have approved entry")
	}
	if approved["tcp:10.0.0.1:22"] {
		t.Error("denied entry should be false")
	}
}

func TestPendingAfterTimeout(t *testing.T) {
	sf := NewSharedFilter(&types.NetworkPolicy{
		DefaultAction:  "deny",
		Interactive:     true,
		ApprovalTimeout: 1,
	})

	// Connection times out
	sf.Allow("tcp", net.ParseIP("93.184.216.34"), 443)

	// Should still appear in pending with "denied" status
	pending := sf.PendingRequests()
	if len(pending) == 0 {
		t.Fatal("timed out connection should still appear in pending")
	}
	found := false
	for _, p := range pending {
		if p.IP == "93.184.216.34" && p.Port == 443 {
			found = true
			if p.Status != "denied" {
				t.Errorf("status = %q, want \"denied\"", p.Status)
			}
			if p.Count != 1 {
				t.Errorf("count = %d, want 1", p.Count)
			}
		}
	}
	if !found {
		t.Error("93.184.216.34:443 not found in pending")
	}
}

func TestPendingCountIncrementsOnRetry(t *testing.T) {
	sf := NewSharedFilter(&types.NetworkPolicy{
		DefaultAction:  "deny",
		Interactive:     true,
		ApprovalTimeout: 1,
	})

	// Two timeouts for the same destination
	sf.Allow("tcp", net.ParseIP("1.2.3.4"), 80)
	sf.Allow("tcp", net.ParseIP("1.2.3.4"), 80)

	pending := sf.PendingRequests()
	for _, p := range pending {
		if p.IP == "1.2.3.4" && p.Port == 80 {
			if p.Count < 2 {
				t.Errorf("count = %d, want >= 2", p.Count)
			}
			return
		}
	}
	t.Error("1.2.3.4:80 not found in pending")
}

func TestNonInteractiveDeniedTracking(t *testing.T) {
	sf := NewSharedFilter(&types.NetworkPolicy{
		DefaultAction: "deny",
	})

	sf.Allow("tcp", net.ParseIP("1.2.3.4"), 443)
	sf.Allow("tcp", net.ParseIP("1.2.3.4"), 443)
	sf.Allow("udp", net.ParseIP("8.8.8.8"), 53)

	pending := sf.PendingRequests()
	if len(pending) != 2 {
		t.Fatalf("expected 2 denied entries, got %d", len(pending))
	}

	for _, p := range pending {
		if p.IP == "1.2.3.4" && p.Port == 443 {
			if p.Count != 2 {
				t.Errorf("count = %d, want 2", p.Count)
			}
			if p.Status != "denied" {
				t.Errorf("status = %q, want \"denied\"", p.Status)
			}
		}
	}
}

func TestPendingStatusUpdatedOnApproval(t *testing.T) {
	sf := NewSharedFilter(&types.NetworkPolicy{
		DefaultAction:  "deny",
		Interactive:     true,
		ApprovalTimeout: 2,
	})

	go func() {
		for i := 0; i < 50; i++ {
			pending := sf.PendingRequests()
			for _, p := range pending {
				if p.Status == "pending" {
					sf.Approve("tcp", p.IP, p.Port)
					return
				}
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	sf.Allow("tcp", net.ParseIP("1.2.3.4"), 443)

	pending := sf.PendingRequests()
	for _, p := range pending {
		if p.IP == "1.2.3.4" && p.Port == 443 {
			if p.Status != "approved" {
				t.Errorf("status = %q, want \"approved\"", p.Status)
			}
			return
		}
	}
}
