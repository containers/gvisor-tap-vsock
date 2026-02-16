package dnscache

import (
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func ip(s string) net.IPAddr { return net.IPAddr{IP: net.ParseIP(s)} }

// --- Normal cases ---

func TestPutAndGet(t *testing.T) {
	c := New(100, time.Minute)
	ips := []net.IPAddr{ip("1.2.3.4")}
	c.Put("example.com", ips)

	got, ok := c.Get("example.com")
	if !ok {
		t.Fatal("expected hit")
	}
	if len(got) != 1 || !got[0].IP.Equal(ips[0].IP) {
		t.Fatalf("got %v, want %v", got, ips)
	}
}

func TestGetMiss(t *testing.T) {
	c := New(100, time.Minute)
	got, ok := c.Get("no.such.domain")
	if ok || got != nil {
		t.Fatalf("expected miss, got %v %v", got, ok)
	}
}

func TestPutOverwrite(t *testing.T) {
	c := New(100, time.Minute)
	c.Put("example.com", []net.IPAddr{ip("1.1.1.1")})
	c.Put("example.com", []net.IPAddr{ip("2.2.2.2")})

	got, ok := c.Get("example.com")
	if !ok {
		t.Fatal("expected hit")
	}
	if len(got) != 1 || !got[0].IP.Equal(net.ParseIP("2.2.2.2")) {
		t.Fatalf("got %v, want 2.2.2.2", got)
	}
	if c.Len() != 1 {
		t.Fatalf("expected len 1, got %d", c.Len())
	}
}

func TestMultipleKeys(t *testing.T) {
	c := New(100, time.Minute)
	c.Put("a.com", []net.IPAddr{ip("1.1.1.1")})
	c.Put("b.com", []net.IPAddr{ip("2.2.2.2")})

	a, ok := c.Get("a.com")
	if !ok || !a[0].IP.Equal(net.ParseIP("1.1.1.1")) {
		t.Fatalf("a.com: got %v %v", a, ok)
	}
	b, ok := c.Get("b.com")
	if !ok || !b[0].IP.Equal(net.ParseIP("2.2.2.2")) {
		t.Fatalf("b.com: got %v %v", b, ok)
	}
}

func TestMultipleIPs(t *testing.T) {
	c := New(100, time.Minute)
	ips := []net.IPAddr{ip("1.1.1.1"), ip("2.2.2.2"), ip("3.3.3.3")}
	c.Put("multi.com", ips)

	got, ok := c.Get("multi.com")
	if !ok || len(got) != 3 {
		t.Fatalf("expected 3 IPs, got %v %v", got, ok)
	}
	for i, want := range ips {
		if !got[i].IP.Equal(want.IP) {
			t.Fatalf("ip[%d]: got %v, want %v", i, got[i], want)
		}
	}
}

// --- TTL / expiry ---

func TestGetExpired(t *testing.T) {
	c := New(100, 10*time.Millisecond)
	c.Put("expire.com", []net.IPAddr{ip("1.1.1.1")})
	time.Sleep(20 * time.Millisecond)

	got, ok := c.Get("expire.com")
	if ok || got != nil {
		t.Fatalf("expected miss after expiry, got %v %v", got, ok)
	}
	if c.Len() != 0 {
		t.Fatalf("expected entry cleaned up, len=%d", c.Len())
	}
}

func TestGetNotYetExpired(t *testing.T) {
	c := New(100, time.Second)
	c.Put("fresh.com", []net.IPAddr{ip("1.1.1.1")})

	got, ok := c.Get("fresh.com")
	if !ok {
		t.Fatal("expected hit within TTL")
	}
	if !got[0].IP.Equal(net.ParseIP("1.1.1.1")) {
		t.Fatalf("got %v", got)
	}
}

func TestPutResetsExpiry(t *testing.T) {
	c := New(100, 30*time.Millisecond)
	c.Put("reset.com", []net.IPAddr{ip("1.1.1.1")})
	time.Sleep(15 * time.Millisecond)

	// Overwrite resets the TTL clock.
	c.Put("reset.com", []net.IPAddr{ip("2.2.2.2")})
	time.Sleep(20 * time.Millisecond)

	got, ok := c.Get("reset.com")
	if !ok {
		t.Fatal("expected hit after TTL reset")
	}
	if !got[0].IP.Equal(net.ParseIP("2.2.2.2")) {
		t.Fatalf("got %v", got)
	}
}

// --- LRU eviction ---

func TestEvictionRemovesLRU(t *testing.T) {
	c := New(3, time.Minute)
	c.Put("a.com", []net.IPAddr{ip("1.1.1.1")})
	c.Put("b.com", []net.IPAddr{ip("2.2.2.2")})
	c.Put("c.com", []net.IPAddr{ip("3.3.3.3")})

	// This should evict a.com (LRU).
	c.Put("d.com", []net.IPAddr{ip("4.4.4.4")})

	if _, ok := c.Get("a.com"); ok {
		t.Fatal("a.com should have been evicted")
	}
	for _, d := range []string{"b.com", "c.com", "d.com"} {
		if _, ok := c.Get(d); !ok {
			t.Fatalf("%s should still be present", d)
		}
	}
}

func TestGetPromotesToFront(t *testing.T) {
	c := New(3, time.Minute)
	c.Put("a.com", []net.IPAddr{ip("1.1.1.1")})
	c.Put("b.com", []net.IPAddr{ip("2.2.2.2")})
	c.Put("c.com", []net.IPAddr{ip("3.3.3.3")})

	// Promote a.com to front; b.com is now LRU.
	c.Get("a.com")

	c.Put("d.com", []net.IPAddr{ip("4.4.4.4")})

	if _, ok := c.Get("b.com"); ok {
		t.Fatal("b.com should have been evicted (was LRU after a.com promoted)")
	}
	if _, ok := c.Get("a.com"); !ok {
		t.Fatal("a.com should still be present (was promoted)")
	}
}

func TestEvictionChain(t *testing.T) {
	cap := 5
	c := New(cap, time.Minute)
	for i := 0; i < cap; i++ {
		c.Put(strings.Repeat("a", i+1)+".com", []net.IPAddr{ip("1.1.1.1")})
	}
	// Insert 10 more; each should evict one.
	for i := 0; i < 10; i++ {
		c.Put(strings.Repeat("z", i+1)+".com", []net.IPAddr{ip("9.9.9.9")})
		if c.Len() != cap {
			t.Fatalf("after extra insert %d: len=%d, want %d", i, c.Len(), cap)
		}
	}
}

// --- Edge cases ---

func TestEmptyDomainKey(t *testing.T) {
	c := New(100, time.Minute)
	c.Put("", []net.IPAddr{ip("1.1.1.1")})

	got, ok := c.Get("")
	if !ok {
		t.Fatal("expected hit for empty domain key")
	}
	if !got[0].IP.Equal(net.ParseIP("1.1.1.1")) {
		t.Fatalf("got %v", got)
	}
}

func TestEmptyIPSlice(t *testing.T) {
	c := New(100, time.Minute)
	c.Put("x.com", []net.IPAddr{})

	got, ok := c.Get("x.com")
	if !ok {
		t.Fatal("expected hit for empty IP slice")
	}
	if len(got) != 0 {
		t.Fatalf("expected empty slice, got %v", got)
	}
}

func TestSingleEntryCapacity(t *testing.T) {
	c := New(1, time.Minute)
	c.Put("a.com", []net.IPAddr{ip("1.1.1.1")})
	c.Put("b.com", []net.IPAddr{ip("2.2.2.2")})

	if _, ok := c.Get("a.com"); ok {
		t.Fatal("a.com should have been evicted")
	}
	if _, ok := c.Get("b.com"); !ok {
		t.Fatal("b.com should be present")
	}
}

func TestIPv4AndIPv6(t *testing.T) {
	c := New(100, time.Minute)
	ips := []net.IPAddr{ip("93.184.216.34"), ip("2606:2800:220:1:248:1893:25c8:1946")}
	c.Put("example.com", ips)

	got, ok := c.Get("example.com")
	if !ok || len(got) != 2 {
		t.Fatalf("expected 2 IPs, got %v %v", got, ok)
	}
	if !got[0].IP.Equal(ips[0].IP) || !got[1].IP.Equal(ips[1].IP) {
		t.Fatalf("got %v, want %v", got, ips)
	}
}

// --- Construction panics ---

func TestNewPanicsOnZeroCapacity(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for zero capacity")
		}
	}()
	New(0, 5*time.Minute)
}

func TestNewPanicsOnZeroTTL(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for zero TTL")
		}
	}()
	New(100, 0)
}

func TestNewPanicsOnNegativeTTL(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for negative TTL")
		}
	}()
	New(100, -1)
}

func TestLargeDomainName(t *testing.T) {
	c := New(100, time.Minute)
	domain := strings.Repeat("a", 253)
	c.Put(domain, []net.IPAddr{ip("1.1.1.1")})

	got, ok := c.Get(domain)
	if !ok {
		t.Fatal("expected hit for large domain name")
	}
	if !got[0].IP.Equal(net.ParseIP("1.1.1.1")) {
		t.Fatalf("got %v", got)
	}
}

// --- Concurrency ---

func TestConcurrentPutGet(t *testing.T) {
	c := New(1000, time.Minute)
	domains := []string{"a.com", "b.com", "c.com", "d.com", "e.com"}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			d := domains[i%len(domains)]
			c.Put(d, []net.IPAddr{ip("1.1.1.1")})
			c.Get(d)
		}(i)
	}
	wg.Wait()
}

func TestConcurrentEviction(t *testing.T) {
	cap := 50
	c := New(cap, time.Minute)
	// Pre-fill to capacity.
	for i := 0; i < cap; i++ {
		c.Put(strings.Repeat("x", i+1), []net.IPAddr{ip("1.1.1.1")})
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c.Put(strings.Repeat("y", i+1), []net.IPAddr{ip("2.2.2.2")})
			if c.Len() > cap {
				t.Errorf("len %d exceeds capacity %d", c.Len(), cap)
			}
		}(i)
	}
	wg.Wait()

	if c.Len() > cap {
		t.Fatalf("final len %d exceeds capacity %d", c.Len(), cap)
	}
}

// --- Security-relevant ---

func TestExpiredEntryNeverReturned(t *testing.T) {
	c := New(100, 10*time.Millisecond)
	c.Put("secret.com", []net.IPAddr{ip("10.0.0.1")})
	time.Sleep(20 * time.Millisecond)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := c.Get("secret.com"); ok {
				t.Error("expired entry was returned")
			}
		}()
	}
	wg.Wait()
}

func TestOverwriteIsAtomic(t *testing.T) {
	c := New(100, time.Minute)
	oldIPs := []net.IPAddr{ip("1.1.1.1"), ip("2.2.2.2")}
	newIPs := []net.IPAddr{ip("3.3.3.3"), ip("4.4.4.4")}
	c.Put("atomic.com", oldIPs)

	var wg sync.WaitGroup
	// Writer goroutine.
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.Put("atomic.com", newIPs)
	}()

	// Reader goroutines.
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, ok := c.Get("atomic.com")
			if !ok {
				return
			}
			// Must be entirely old or entirely new, never mixed.
			if len(got) != 2 {
				t.Errorf("unexpected IP count: %d", len(got))
				return
			}
			first := got[0].IP.String()
			second := got[1].IP.String()
			isOld := first == "1.1.1.1" && second == "2.2.2.2"
			isNew := first == "3.3.3.3" && second == "4.4.4.4"
			if !isOld && !isNew {
				t.Errorf("partial update observed: %v", got)
			}
		}()
	}
	wg.Wait()
}

// --- Memory usage ---

func TestMemoryUsageAtCapacity(t *testing.T) {
	const entries = DefaultMaxEntries

	// Baseline: force GC twice so finalizers run, then read heap.
	runtime.GC()
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	c := New(entries, time.Minute)
	for i := 0; i < entries; i++ {
		domain := fmt.Sprintf("domain-%d.example.com.", i)
		c.Put(domain, []net.IPAddr{ip("1.2.3.4")})
	}

	runtime.KeepAlive(c)
	runtime.GC()
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(c)

	bytes := after.HeapAlloc - before.HeapAlloc
	perEntry := bytes / uint64(entries)
	t.Logf("cache full (%d entries): ~%d MB total, ~%d bytes/entry", entries, bytes/(1024*1024), perEntry)

	// Upper bound: 5 MB for 10k entries (~512 bytes/entry).
	// Actual usage is ~2.5 MB (~250 bytes/entry).
	const maxBytes = 5 * 1024 * 1024
	if bytes > maxBytes {
		t.Fatalf("memory usage %d bytes exceeds %d byte limit", bytes, maxBytes)
	}
}
