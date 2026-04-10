package forwarder

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
	log "github.com/sirupsen/logrus"
)

// NetworkFilter evaluates outbound connections against a NetworkPolicy.
type NetworkFilter struct {
	defaultDeny bool
	rules       []parsedRule
}

type parsedRule struct {
	allow   bool
	network *net.IPNet // nil means match all IPs
	ports   map[int]struct{}
	proto   string // "tcp", "udp", or "" for both
}

// NewNetworkFilter creates a filter from a NetworkPolicy.
// Returns nil if policy is nil (no filtering).
func NewNetworkFilter(policy *types.NetworkPolicy) *NetworkFilter {
	if policy == nil {
		return nil
	}

	f := &NetworkFilter{
		defaultDeny: policy.DefaultAction == "deny",
	}

	for _, r := range policy.Rules {
		pr := parsedRule{
			allow: r.Action == "allow",
			proto: r.Protocol,
		}
		if r.CIDR != "" {
			_, ipNet, err := net.ParseCIDR(r.CIDR)
			if err != nil {
				log.Warnf("network policy: invalid CIDR %q, skipping rule", r.CIDR)
				continue
			}
			pr.network = ipNet
		}
		if len(r.Ports) > 0 {
			pr.ports = make(map[int]struct{}, len(r.Ports))
			for _, p := range r.Ports {
				pr.ports[p] = struct{}{}
			}
		}
		f.rules = append(f.rules, pr)
	}

	return f
}

// Allow checks whether a connection to the given address and port is permitted.
// protocol is "tcp" or "udp".
func (f *NetworkFilter) Allow(protocol string, ip net.IP, port int) bool {
	if f == nil {
		return true
	}

	for _, r := range f.rules {
		if !r.matches(protocol, ip, port) {
			continue
		}
		if r.allow {
			log.Debugf("network policy: ALLOW %s %s:%d (matched rule)", protocol, ip, port)
		} else {
			log.Infof("network policy: DENY %s %s:%d (matched rule)", protocol, ip, port)
		}
		return r.allow
	}

	if f.defaultDeny {
		log.Infof("network policy: DENY %s %s:%d (default deny)", protocol, ip, port)
		return false
	}
	return true
}

func (r *parsedRule) matches(protocol string, ip net.IP, port int) bool {
	if r.proto != "" && r.proto != protocol {
		return false
	}
	if r.network != nil && !r.network.Contains(ip) {
		return false
	}
	if r.ports != nil {
		if _, ok := r.ports[port]; !ok {
			return false
		}
	}
	return true
}

// AllowAddr is a convenience that parses a host:port string.
func (f *NetworkFilter) AllowAddr(protocol, addr string) bool {
	if f == nil {
		return true
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		log.Warnf("network policy: cannot parse address %q: %v", addr, err)
		return !f.defaultDeny
	}
	ip := net.ParseIP(host)
	if ip == nil {
		log.Warnf("network policy: cannot parse IP %q", host)
		return !f.defaultDeny
	}
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)
	return f.Allow(protocol, ip, port)
}

// ConnectionRequest represents an outbound connection that was denied or is awaiting approval.
type ConnectionRequest struct {
	Protocol string `json:"protocol"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Count    int    `json:"count"`
	Status   string `json:"status"` // "pending", "denied", "approved"
	Time     string `json:"time"`
	LastSeen string `json:"last_seen"`
}

// Event represents an SSE event sent to subscribers.
type Event struct {
	Type string      `json:"type"` // "network_denied", "network_approved", "dns_denied", "dns_allowed"
	Data interface{} `json:"data"`
}

// SharedFilter provides a thread-safe filter with optional interactive approval.
// In secure mode (interactive), denied connections are held pending for external
// approval via the HTTP API, and notifications are sent to the notification socket.
// All denied connections are tracked regardless of mode.
type SharedFilter struct {
	mu     sync.RWMutex
	filter *NetworkFilter

	// interactive mode fields
	interactive     bool
	approvalTimeout time.Duration
	approved        map[string]bool           // "proto:ip:port" → allowed
	waiters         map[string]chan bool       // blocking channels for pending requests
	denied          map[string]*ConnectionRequest // all denied/pending connections
	notifyFn        func(types.NotificationMessage)

	// SSE subscribers
	sseSubscribers map[chan Event]struct{}
}

func NewSharedFilter(policy *types.NetworkPolicy) *SharedFilter {
	sf := &SharedFilter{
		filter:         NewNetworkFilter(policy),
		denied:         make(map[string]*ConnectionRequest),
		sseSubscribers: make(map[chan Event]struct{}),
	}
	if policy != nil && policy.Interactive {
		sf.interactive = true
		sf.approved = make(map[string]bool)
		sf.waiters = make(map[string]chan bool)
		sf.approvalTimeout = 30 * time.Second
		if policy.ApprovalTimeout > 0 {
			sf.approvalTimeout = time.Duration(policy.ApprovalTimeout) * time.Second
		}
	}
	return sf
}

// Subscribe returns a channel that receives SSE events. Call Unsubscribe to clean up.
func (sf *SharedFilter) Subscribe() chan Event {
	sf.mu.Lock()
	defer sf.mu.Unlock()
	ch := make(chan Event, 50)
	sf.sseSubscribers[ch] = struct{}{}
	return ch
}

// Unsubscribe removes a subscriber channel.
func (sf *SharedFilter) Unsubscribe(ch chan Event) {
	sf.mu.Lock()
	defer sf.mu.Unlock()
	delete(sf.sseSubscribers, ch)
	close(ch)
}

func (sf *SharedFilter) publishEvent(evt Event) {
	n := len(sf.sseSubscribers)
	log.Infof("SSE: publishing %s to %d subscriber(s)", evt.Type, n)
	for ch := range sf.sseSubscribers {
		select {
		case ch <- evt:
			log.Debugf("SSE: delivered %s to subscriber", evt.Type)
		default:
			log.Warnf("SSE: dropped %s event (subscriber slow)", evt.Type)
		}
	}
}

// SetNotifyFunc sets the callback used to send notifications when connections
// are pending approval. This is typically wired to the notification socket.
func (sf *SharedFilter) SetNotifyFunc(fn func(types.NotificationMessage)) {
	sf.mu.Lock()
	defer sf.mu.Unlock()
	sf.notifyFn = fn
}

func (sf *SharedFilter) Allow(protocol string, ip net.IP, port int) bool {
	sf.mu.RLock()
	allowed := sf.filter.Allow(protocol, ip, port)
	interactive := sf.interactive
	sf.mu.RUnlock()

	if allowed {
		return true
	}

	if !interactive {
		sf.trackDenied(protocol, ip, port)
		return false
	}

	return sf.waitForApproval(protocol, ip, port)
}

func (sf *SharedFilter) trackDenied(protocol string, ip net.IP, port int) {
	sf.mu.Lock()
	key := connectionKey(protocol, ip, port)
	now := time.Now().UTC().Format(time.RFC3339)
	var req *ConnectionRequest
	if d, ok := sf.denied[key]; ok {
		d.Count++
		d.LastSeen = now
		req = d
	} else {
		req = &ConnectionRequest{
			Protocol: protocol,
			IP:       ip.String(),
			Port:     port,
			Count:    1,
			Status:   "denied",
			Time:     now,
			LastSeen: now,
		}
		sf.denied[key] = req
	}
	sf.publishEvent(Event{Type: "network_denied", Data: *req})
	sf.mu.Unlock()
}

func (sf *SharedFilter) AllowAddr(protocol, addr string) bool {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return sf.filter.AllowAddr(protocol, addr)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return sf.filter.AllowAddr(protocol, addr)
	}
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)
	return sf.Allow(protocol, ip, port)
}

func connectionKey(protocol string, ip net.IP, port int) string {
	return fmt.Sprintf("%s:%s:%d", protocol, ip.String(), port)
}

func (sf *SharedFilter) waitForApproval(protocol string, ip net.IP, port int) bool {
	key := connectionKey(protocol, ip, port)

	sf.mu.Lock()

	// Check if already approved/denied from a previous interactive decision
	if decision, ok := sf.approved[key]; ok {
		sf.mu.Unlock()
		if decision {
			log.Debugf("network policy: ALLOW %s (cached approval)", key)
		} else {
			log.Debugf("network policy: DENY %s (cached denial)", key)
		}
		return decision
	}

	now := time.Now().UTC().Format(time.RFC3339)

	// Check if there's already a pending request for this key — join it
	if ch, ok := sf.waiters[key]; ok {
		if d, ok := sf.denied[key]; ok {
			d.Count++
			d.LastSeen = now
		}
		sf.mu.Unlock()
		log.Debugf("network policy: waiting on existing approval for %s", key)
		select {
		case result := <-ch:
			return result
		case <-time.After(sf.approvalTimeout):
			log.Infof("network policy: DENY %s (approval timeout)", key)
			return false
		}
	}

	// Create a new pending request
	ch := make(chan bool, 10) // buffered so multiple waiters can receive
	sf.waiters[key] = ch
	var req *ConnectionRequest
	if d, ok := sf.denied[key]; ok {
		// Preserve count from previous attempts
		d.Count++
		d.Status = "pending"
		d.LastSeen = now
		req = d
	} else {
		req = &ConnectionRequest{
			Protocol: protocol,
			IP:       ip.String(),
			Port:     port,
			Count:    1,
			Status:   "pending",
			Time:     now,
			LastSeen: now,
		}
		sf.denied[key] = req
	}
	sf.publishEvent(Event{Type: "network_pending", Data: *req})

	// Send notification
	if sf.notifyFn != nil {
		sf.notifyFn(types.NotificationMessage{
			NotificationType: types.NetworkPolicyPending,
			Details: map[string]string{
				"protocol": protocol,
				"ip":       ip.String(),
				"port":     fmt.Sprint(port),
			},
		})
	}

	sf.mu.Unlock()

	log.Infof("network policy: PENDING %s — waiting for approval (timeout %s)", key, sf.approvalTimeout)

	select {
	case result := <-ch:
		return result
	case <-time.After(sf.approvalTimeout):
		sf.mu.Lock()
		delete(sf.waiters, key)
		// Keep the entry in denied but update status
		if d, ok := sf.denied[key]; ok {
			d.Status = "denied"
		}
		sf.mu.Unlock()
		log.Infof("network policy: DENY %s (approval timeout)", key)
		return false
	}
}

// Approve allows a pending or future connection. The key format is "proto:ip:port"
// or just "ip:port" (applies to both TCP and UDP).
func (sf *SharedFilter) Approve(protocol, ip string, port int) {
	sf.decide(protocol, ip, port, true)
}

// Deny denies a pending or future connection.
func (sf *SharedFilter) Deny(protocol, ip string, port int) {
	sf.decide(protocol, ip, port, false)
}

func (sf *SharedFilter) decide(protocol, ip string, port int, allow bool) {
	sf.mu.Lock()
	defer sf.mu.Unlock()

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		log.Warnf("network policy: invalid IP in decision: %q", ip)
		return
	}

	key := connectionKey(protocol, parsedIP, port)
	sf.approved[key] = allow

	action := "DENY"
	if allow {
		action = "ALLOW"
		// Also add a dynamic rule to the filter so future connections are fast-pathed
		sf.filter = addDynamicRule(sf.filter, protocol, ip, port, allow)
	}
	log.Infof("network policy: %s %s (interactive decision)", action, key)

	// Update denied entry status and publish event
	evtType := "network_denied"
	if allow {
		evtType = "network_approved"
	}
	if d, ok := sf.denied[key]; ok {
		if allow {
			d.Status = "approved"
		} else {
			d.Status = "denied"
		}
		sf.publishEvent(Event{Type: evtType, Data: *d})
	} else {
		sf.publishEvent(Event{Type: evtType, Data: ConnectionRequest{
			Protocol: protocol, IP: ip, Port: port, Status: evtType, Count: 0,
		}})
	}

	// Signal any pending waiters
	if ch, ok := sf.waiters[key]; ok {
		// Send to all waiters (buffered channel)
		for {
			select {
			case ch <- allow:
			default:
				goto done
			}
		}
	done:
		delete(sf.waiters, key)
	}
}

// AutoAllowIP adds a blanket allow rule for an IP (all ports, all protocols).
// Called by the DNS server when a domain resolves successfully, so the user
// only needs to approve the domain via DNS — the TCP/UDP connection to the
// resolved IP is automatically allowed.
func (sf *SharedFilter) AutoAllowIP(ip net.IP, domain string) {
	if sf == nil {
		return
	}
	sf.mu.Lock()
	defer sf.mu.Unlock()

	if sf.filter == nil {
		return
	}

	_, ipNet, err := net.ParseCIDR(ip.String() + "/32")
	if err != nil {
		return
	}

	// Check if we already have a rule for this IP
	for _, r := range sf.filter.rules {
		if r.allow && r.network != nil && r.network.String() == ipNet.String() && r.ports == nil {
			return // already allowed
		}
	}

	rule := parsedRule{
		allow:   true,
		network: ipNet,
	}
	sf.filter.rules = append([]parsedRule{rule}, sf.filter.rules...)
	log.Infof("network policy: auto-allow IP %s (resolved from DNS %q)", ip, domain)
}

// addDynamicRule adds a new allow/deny rule to the filter.
func addDynamicRule(f *NetworkFilter, protocol, ip string, port int, allow bool) *NetworkFilter {
	if f == nil {
		f = &NetworkFilter{defaultDeny: true}
	}

	_, ipNet, err := net.ParseCIDR(ip + "/32")
	if err != nil {
		return f
	}

	rule := parsedRule{
		allow:   allow,
		network: ipNet,
		proto:   protocol,
		ports:   map[int]struct{}{port: {}},
	}
	// Prepend so dynamic rules are checked first
	f.rules = append([]parsedRule{rule}, f.rules...)
	return f
}

// PendingRequests returns a snapshot of all denied/pending connection requests.
func (sf *SharedFilter) PendingRequests() []ConnectionRequest {
	sf.mu.RLock()
	defer sf.mu.RUnlock()
	result := make([]ConnectionRequest, 0, len(sf.denied))
	for _, r := range sf.denied {
		result = append(result, *r)
	}
	return result
}

// AllConnections returns all tracked connections: denied, pending, and approved.
func (sf *SharedFilter) AllConnections() []ConnectionRequest {
	sf.mu.RLock()
	defer sf.mu.RUnlock()
	result := make([]ConnectionRequest, 0, len(sf.denied))
	for _, r := range sf.denied {
		result = append(result, *r)
	}
	return result
}

// ApprovedList returns all cached interactive decisions.
func (sf *SharedFilter) ApprovedList() map[string]bool {
	sf.mu.RLock()
	defer sf.mu.RUnlock()
	result := make(map[string]bool, len(sf.approved))
	for k, v := range sf.approved {
		result[k] = v
	}
	return result
}

// Mux returns an HTTP handler for the network policy API.
func (sf *SharedFilter) Mux() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/pending", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(sf.PendingRequests())
	})

	mux.HandleFunc("/approved", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(sf.ApprovedList())
	})

	mux.HandleFunc("/allow", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "post only", http.StatusBadRequest)
			return
		}
		var req ConnectionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		sf.Approve(req.Protocol, req.IP, req.Port)
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("/deny", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "post only", http.StatusBadRequest)
			return
		}
		var req ConnectionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		sf.Deny(req.Protocol, req.IP, req.Port)
		w.WriteHeader(http.StatusOK)
	})

	// All connections ever attempted (denied, pending, approved)
	mux.HandleFunc("/connections", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(sf.AllConnections())
	})

	// SSE endpoint for real-time events
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming not supported", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		ch := sf.Subscribe()
		defer sf.Unsubscribe(ch)

		// Send initial state
		data, _ := json.Marshal(sf.AllConnections())
		fmt.Fprintf(w, "event: init\ndata: %s\n\n", data)
		flusher.Flush()

		ctx := r.Context()
		for {
			select {
			case <-ctx.Done():
				return
			case evt, ok := <-ch:
				if !ok {
					return
				}
				data, _ := json.Marshal(evt.Data)
				log.Infof("SSE: sending event %s: %s", evt.Type, string(data))
				fmt.Fprintf(w, "event: %s\ndata: %s\n\n", evt.Type, data)
				flusher.Flush()
			}
		}
	})

	return mux
}

// PublishDNSEvent sends a DNS-related event to all SSE subscribers.
func (sf *SharedFilter) PublishDNSEvent(evtType string, data interface{}) {
	sf.mu.RLock()
	defer sf.mu.RUnlock()
	sf.publishEvent(Event{Type: evtType, Data: data})
}

func (sf *SharedFilter) Update(policy *types.NetworkPolicy) {
	sf.mu.Lock()
	defer sf.mu.Unlock()
	sf.filter = NewNetworkFilter(policy)
}
