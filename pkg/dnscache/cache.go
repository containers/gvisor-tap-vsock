package dnscache

import (
	"container/list"
	"net"
	"sync"
	"time"
)

const (
	// DefaultMaxEntries is a generous default for sandboxed environments
	// that typically query tens of domains.
	DefaultMaxEntries = 10000

	// DefaultTTL is the expiry for cached entries. Kept short to avoid
	// serving stale results to clients without their own cache.
	DefaultTTL = 5 * time.Second
)

type entry struct {
	domain    string // key stored in entry for O(1) eviction (list element -> map delete)
	ips       []net.IPAddr
	expiresAt time.Time
}

// DNSCache is a thread-safe LRU cache mapping domain names to resolved IP
// addresses. Each entry has a TTL after which it is lazily evicted on access.
// When the cache is full, the least recently used entry is evicted.
type DNSCache struct {
	mu         sync.Mutex
	items      map[string]*list.Element // domain -> list element
	order      *list.List               // front = most recently used, back = LRU
	maxEntries int
	ttl        time.Duration
}

// New creates a DNSCache with the given capacity and TTL.
// It panics if maxEntries <= 0 or ttl <= 0.
func New(maxEntries int, ttl time.Duration) *DNSCache {
	if maxEntries <= 0 {
		panic("dnscache: maxEntries must be > 0")
	}
	if ttl <= 0 {
		panic("dnscache: ttl must be > 0")
	}
	return &DNSCache{
		items:      make(map[string]*list.Element),
		order:      list.New(),
		maxEntries: maxEntries,
		ttl:        ttl,
	}
}

// Put stores the domain-to-IPs mapping. If the domain already exists, its IPs
// and expiry are updated and it is promoted to the front (most recently used).
// If the cache is at capacity, the least recently used entry is evicted.
func (c *DNSCache) Put(domain string, ips []net.IPAddr) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if el, ok := c.items[domain]; ok {
		// Update existing entry and move to front.
		e := el.Value.(*entry)
		e.ips = ips
		e.expiresAt = time.Now().Add(c.ttl)
		c.order.MoveToFront(el)
		return
	}

	// Evict LRU if at capacity.
	if len(c.items) >= c.maxEntries {
		c.evictLRU()
	}

	el := c.order.PushFront(&entry{
		domain:    domain,
		ips:       ips,
		expiresAt: time.Now().Add(c.ttl),
	})
	c.items[domain] = el
}

// Get returns the cached IPs for the domain. On a hit that has not expired the
// entry is promoted to the front. Expired entries are lazily deleted.
// Returns (nil, false) on miss or expiry.
func (c *DNSCache) Get(domain string) ([]net.IPAddr, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.items[domain]
	if !ok {
		return nil, false
	}

	e := el.Value.(*entry)
	if time.Now().After(e.expiresAt) {
		// Lazy cleanup of expired entry.
		c.order.Remove(el)
		delete(c.items, domain)
		return nil, false
	}

	c.order.MoveToFront(el)
	return e.ips, true
}

// Len returns the current number of entries in the cache.
func (c *DNSCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}

// evictLRU removes the least recently used entry. Must be called with mu held.
func (c *DNSCache) evictLRU() {
	el := c.order.Back()
	if el == nil {
		return
	}
	c.order.Remove(el)
	delete(c.items, el.Value.(*entry).domain)
}
