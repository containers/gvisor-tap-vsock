package types

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// EgressRule matches one transport, destination CIDR, and optional destination
// port. Protocol must be explicitly "tcp" or "udp". An empty CIDR is only
// accepted when the policy sets allowAny: true, so a missing field cannot
// silently turn a rule into an allow-all rule. Port 0 means any port.
type EgressRule struct {
	Protocol string `yaml:"protocol,omitempty" json:"protocol,omitempty"`
	CIDR     string `yaml:"cidr,omitempty" json:"cidr,omitempty"`
	Port     uint16 `yaml:"port,omitempty" json:"port,omitempty"`
	// Domain is an exact name, *.example.com, **.example.com, or a
	// single-label glob. It is mutually exclusive with CIDR.
	Domain string `yaml:"domain,omitempty" json:"domain,omitempty"`
}

// EgressPolicy is a host-enforced default-deny policy. Allow rules are
// evaluated after deny rules. Revision is copied into every decision record;
// it is intentionally a string so callers can use an opaque generation token.
type EgressPolicy struct {
	Revision  string       `yaml:"revision,omitempty" json:"revision,omitempty"`
	SandboxID string       `yaml:"sandboxID,omitempty" json:"sandboxID,omitempty"`
	AllowAny  bool         `yaml:"allowAny,omitempty" json:"allowAny,omitempty"`
	Allow     []EgressRule `yaml:"allow,omitempty" json:"allow,omitempty"`
	Deny      []EgressRule `yaml:"deny,omitempty" json:"deny,omitempty"`
	// AuditLog is the path of an append-only JSONL decision log. An empty path
	// disables the file log, but decisions are still enforced.
	AuditLog string `yaml:"auditLog,omitempty" json:"auditLog,omitempty"`
}

// EgressDecision is one policy outcome. It intentionally contains no headers,
// payloads, credentials, or hostnames that were not already in the policy.
type EgressDecision struct {
	Time        string `json:"time"`
	SandboxID   string `json:"sandboxId,omitempty"`
	Revision    string `json:"revision"`
	Protocol    string `json:"protocol"`
	Destination string `json:"destination"`
	Port        uint16 `json:"port"`
	Action      string `json:"action"`
	Rule        string `json:"rule"`
}

type compiledEgressRule struct {
	protocol string
	network  *net.IPNet
	domain   *regexp.Regexp
	port     uint16
	any      bool
	source   string
}

func (r compiledEgressRule) matches(protocol string, ip net.IP, port uint16) bool {
	if r.protocol != protocol {
		return false
	}
	if r.port != 0 && r.port != port {
		return false
	}
	if r.any {
		return true
	}
	if r.network == nil {
		return false
	}
	return r.network.Contains(ip)
}

func (r compiledEgressRule) matchesDomain(protocol, name string, port uint16) bool {
	if r.protocol != protocol || r.domain == nil {
		return false
	}
	if r.port != 0 && r.port != port {
		return false
	}
	return r.domain.MatchString(strings.TrimSuffix(strings.ToLower(name), "."))
}

func (r compiledEgressRule) matchesName(name string) bool {
	return r.domain != nil && r.domain.MatchString(strings.TrimSuffix(strings.ToLower(name), "."))
}

type egressSnapshot struct {
	revision  string
	sandboxID string
	allow     []compiledEgressRule
	deny      []compiledEgressRule
	allowAny  bool
}

type resolvedBinding struct {
	name    string
	expires time.Time
}

func (s *egressSnapshot) decide(protocol, address string, port uint16) (bool, string) {
	ip := net.ParseIP(address)
	if ip == nil {
		return false, "invalid-destination"
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	for _, rule := range s.deny {
		if rule.matches(protocol, ip, port) {
			return false, "deny:" + rule.source
		}
	}
	for _, rule := range s.allow {
		if rule.matches(protocol, ip, port) {
			return true, "allow:" + rule.source
		}
	}
	return false, "default-deny"
}

func compileEgressRules(direction string, rules []EgressRule, allowAny bool) ([]compiledEgressRule, error) {
	compiled := make([]compiledEgressRule, 0, len(rules))
	for i, rule := range rules {
		protocol := strings.ToLower(strings.TrimSpace(rule.Protocol))
		if protocol != "tcp" && protocol != "udp" {
			return nil, fmt.Errorf("%s rule %d: protocol must be tcp or udp, got %q", direction, i, rule.Protocol)
		}
		var network *net.IPNet
		var domain *regexp.Regexp
		switch {
		case rule.CIDR != "" && rule.Domain != "":
			return nil, fmt.Errorf("%s rule %d: cidr and domain are mutually exclusive", direction, i)
		case rule.Domain != "":
			parsed, err := compileDomainRule(rule.Domain)
			if err != nil {
				return nil, fmt.Errorf("%s rule %d: %w", direction, i, err)
			}
			domain = parsed
		case rule.CIDR == "":
			if !allowAny || direction == "deny" {
				return nil, fmt.Errorf("%s rule %d: empty cidr is not allowed (set allowAny: true for an allow-all rule)", direction, i)
			}
		default:
			_, parsed, err := net.ParseCIDR(strings.TrimSpace(rule.CIDR))
			if err != nil {
				return nil, fmt.Errorf("%s rule %d: invalid cidr %q: %w", direction, i, rule.CIDR, err)
			}
			network = parsed
		}
		any := rule.CIDR == "" && rule.Domain == ""
		source := fmt.Sprintf("%s %s port=%d", protocol, rule.CIDR, rule.Port)
		if rule.Domain != "" {
			source = fmt.Sprintf("%s domain=%s port=%d", protocol, rule.Domain, rule.Port)
		} else if rule.CIDR == "" {
			source = fmt.Sprintf("%s any port=%d", protocol, rule.Port)
		}
		compiled = append(compiled, compiledEgressRule{
			protocol: protocol,
			network:  network,
			domain:   domain,
			port:     rule.Port,
			any:      any,
			source:   source,
		})
	}
	return compiled, nil
}

// compileDomainRule builds an anchored matcher. A single leading "*." matches
// exactly one additional label; "**." matches one or more labels. Other glob
// characters are restricted to one label so a pattern cannot unexpectedly
// cross a dot boundary.
func compileDomainRule(pattern string) (*regexp.Regexp, error) {
	pattern = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(pattern), "."))
	if pattern == "" || len(pattern) > 253 || strings.ContainsAny(pattern, "\\ ") {
		return nil, fmt.Errorf("invalid domain %q", pattern)
	}
	var expression string
	switch {
	case strings.HasPrefix(pattern, "**."):
		rest := pattern[3:]
		if rest == "" || strings.Contains(rest, "*") {
			return nil, fmt.Errorf("invalid domain %q", pattern)
		}
		expression = `^.+\.` + regexp.QuoteMeta(rest) + `$`
	case strings.HasPrefix(pattern, "*."):
		rest := pattern[2:]
		if rest == "" || strings.Contains(rest, "*") {
			return nil, fmt.Errorf("invalid domain %q", pattern)
		}
		expression = `^[^.]+\.` + regexp.QuoteMeta(rest) + `$`
	default:
		if strings.Contains(pattern, "*") {
			return nil, fmt.Errorf("invalid domain %q", pattern)
		}
		expression = `^` + domainGlobExpression(pattern) + `$`
	}
	compiled, err := regexp.Compile(expression)
	if err != nil {
		return nil, fmt.Errorf("invalid domain %q: %w", pattern, err)
	}
	return compiled, nil
}

func domainGlobExpression(pattern string) string {
	var b strings.Builder
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch c {
		case '?':
			b.WriteString(`[^.]`)
		case '[':
			end := strings.IndexByte(pattern[i+1:], ']')
			if end < 0 {
				b.WriteString(`\[`)
				continue
			}
			class := pattern[i+1 : i+1+end]
			if strings.HasPrefix(class, "!") {
				class = "^" + class[1:]
			}
			b.WriteString("[" + class + "]")
			i += end + 1
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	return b.String()
}

func compileEgressPolicy(policy *EgressPolicy) (*egressSnapshot, error) {
	allow, err := compileEgressRules("allow", policy.Allow, policy.AllowAny)
	if err != nil {
		return nil, err
	}
	deny, err := compileEgressRules("deny", policy.Deny, false)
	if err != nil {
		return nil, err
	}
	revision := policy.Revision
	if revision == "" {
		revision = "0"
	}
	return &egressSnapshot{
		revision:  revision,
		sandboxID: policy.SandboxID,
		allow:     allow,
		deny:      deny,
		allowAny:  policy.AllowAny,
	}, nil
}

// Validate checks the policy before any network service starts.
func (p *EgressPolicy) Validate() error {
	if p == nil {
		return nil
	}
	_, err := compileEgressPolicy(p)
	return err
}

type egressAudit struct {
	mu   sync.Mutex
	file *os.File
}

func openEgressAudit(path string) (*egressAudit, error) {
	if path == "" {
		return nil, nil
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("cannot open egress audit log %q: %w", path, err)
	}
	return &egressAudit{file: file}, nil
}

func (a *egressAudit) record(decision EgressDecision) error {
	if a == nil {
		return nil
	}
	decision.Time = time.Now().UTC().Format(time.RFC3339Nano)
	line, err := json.Marshal(decision)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.file.Write(line); err != nil {
		return err
	}
	return a.file.Sync()
}

func (a *egressAudit) close() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.file.Close()
}

// EgressPolicyHolder provides atomic replacement of the active policy. A nil
// holder, or a holder with no policy, preserves the upstream permissive
// behavior only when the holder was created without required=true.
type trackedEgressFlow struct {
	protocol string
	address  string
	port     uint16
	closer   io.Closer
}

type EgressPolicyHolder struct {
	mu         sync.RWMutex
	snapshot   *egressSnapshot
	audit      *egressAudit
	required   bool
	flows      map[uint64]trackedEgressFlow
	nextFlowID uint64
	// resolved maps a DNS answer IP to the names that produced it. It is
	// bounded and expires so a hostile resolver cannot grow it without limit.
	resolved map[string][]resolvedBinding
}

func NewEgressPolicyHolder(policy *EgressPolicy, required bool) (*EgressPolicyHolder, error) {
	holder := &EgressPolicyHolder{required: required, flows: make(map[uint64]trackedEgressFlow), resolved: make(map[string][]resolvedBinding)}
	if policy == nil {
		if required {
			return nil, fmt.Errorf("egress policy is required but not configured")
		}
		return holder, nil
	}
	snapshot, err := compileEgressPolicy(policy)
	if err != nil {
		return nil, err
	}
	audit, err := openEgressAudit(policy.AuditLog)
	if err != nil {
		return nil, err
	}
	holder.snapshot = snapshot
	holder.audit = audit
	return holder, nil
}

// Enabled reports whether a policy is currently active.
func (h *EgressPolicyHolder) Enabled() bool {
	if h == nil {
		return false
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.snapshot != nil
}

// Revision returns the active revision, or "" when no policy is active.
func (h *EgressPolicyHolder) Revision() string {
	if h == nil {
		return ""
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.snapshot == nil {
		return ""
	}
	return h.snapshot.revision
}

// Update compiles a new policy and swaps it atomically. It never mutates the
// active snapshot. The audit sink is fixed for the lifetime of the holder; a
// changed auditLog path is rejected instead of silently redirecting records.
func (h *EgressPolicyHolder) Update(policy *EgressPolicy) error {
	if h == nil {
		if policy == nil {
			return nil
		}
		return fmt.Errorf("cannot update a nil egress policy holder")
	}
	if policy == nil {
		if h.required {
			return fmt.Errorf("egress policy is required; refusing to remove it")
		}
		h.mu.Lock()
		h.snapshot = nil
		h.mu.Unlock()
		return nil
	}
	if h.audit != nil && policy.AuditLog == "" {
		return fmt.Errorf("cannot disable the active egress audit log")
	}
	if h.audit == nil && policy.AuditLog != "" {
		return fmt.Errorf("cannot add an audit log after startup; restart required")
	}
	snapshot, err := compileEgressPolicy(policy)
	if err != nil {
		return err
	}
	type revocation struct {
		decision EgressDecision
		closer   io.Closer
	}
	var revocations []revocation
	h.mu.Lock()
	h.snapshot = snapshot
	for id, flow := range h.flows {
		allowed, rule := snapshot.decide(flow.protocol, flow.address, flow.port)
		if allowed {
			continue
		}
		delete(h.flows, id)
		revocations = append(revocations, revocation{
			decision: EgressDecision{
				SandboxID:   snapshot.sandboxID,
				Revision:    snapshot.revision,
				Protocol:    flow.protocol,
				Destination: flow.address,
				Port:        flow.port,
				Action:      "deny",
				Rule:        "revoke:" + rule,
			},
			closer: flow.closer,
		})
	}
	audit := h.audit
	h.mu.Unlock()
	for _, revocation := range revocations {
		if audit != nil {
			_ = audit.record(revocation.decision)
		}
		_ = revocation.closer.Close()
	}
	return nil
}

// Track registers an established flow so a later policy revision can close it.
// The caller already evaluated Allows for the initial dial; Track only audits
// a denial that happened in the race between that check and registration.
// A nil policy or a nil closer returns 0 without tracking.
func (h *EgressPolicyHolder) Track(protocol, address string, port uint16, closer io.Closer) uint64 {
	if h == nil || closer == nil {
		return 0
	}
	h.mu.Lock()
	snapshot := h.snapshot
	if snapshot == nil {
		h.mu.Unlock()
		return 0
	}
	allowed, rule := snapshot.decide(protocol, address, port)
	if !allowed && rule == "default-deny" {
		if name, ok := h.resolvedNameLocked(protocol, address, port); ok {
			allowed = true
			rule = "allow:domain " + name
		}
	}
	if !allowed {
		audit := h.audit
		h.mu.Unlock()
		if audit != nil {
			_ = audit.record(EgressDecision{
				SandboxID:   snapshot.sandboxID,
				Revision:    snapshot.revision,
				Protocol:    protocol,
				Destination: address,
				Port:        port,
				Action:      "deny",
				Rule:        rule,
			})
		}
		return 0
	}
	h.nextFlowID++
	id := h.nextFlowID
	h.flows[id] = trackedEgressFlow{protocol: protocol, address: address, port: port, closer: closer}
	h.mu.Unlock()
	return id
}

// Untrack removes a flow that ended normally. It is safe to call after Close
// or after a policy revocation already removed the flow.
func (h *EgressPolicyHolder) Untrack(id uint64) {
	if h == nil || id == 0 {
		return
	}
	h.mu.Lock()
	delete(h.flows, id)
	h.mu.Unlock()
}

// Allows evaluates a flow and writes one audit record when an audit sink is
// configured. A nil holder allows the flow for upstream compatibility.
func (h *EgressPolicyHolder) Allows(protocol, address string, port uint16) bool {
	if h == nil {
		return true
	}
	h.mu.RLock()
	snapshot := h.snapshot
	audit := h.audit
	allowed := true
	rule := "no-policy"
	if snapshot != nil {
		allowed, rule = snapshot.decide(protocol, address, port)
		if !allowed && rule == "default-deny" {
			if name, ok := h.resolvedNameLocked(protocol, address, port); ok {
				allowed = true
				rule = "allow:domain " + name
			}
		}
	}
	h.mu.RUnlock()
	action := "deny"
	if allowed {
		action = "allow"
	}
	if snapshot != nil && audit != nil {
		// Audit failure must not change the enforcement decision; the
		// caller-facing decision is already computed and fail-closed.
		_ = audit.record(EgressDecision{
			SandboxID:   snapshot.sandboxID,
			Revision:    snapshot.revision,
			Protocol:    protocol,
			Destination: address,
			Port:        port,
			Action:      action,
			Rule:        rule,
		})
	}
	return allowed
}

// DNSAllowed reports whether the guest may resolve name. CIDR rules need DNS
// to map hostnames to their addresses, so any static allow also permits
// resolution; domain-only policies permit only matching names.
func (h *EgressPolicyHolder) DNSAllowed(name string) bool {
	if h == nil {
		return true
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	snapshot := h.snapshot
	if snapshot == nil {
		return true
	}
	normalized := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	for _, rule := range snapshot.deny {
		if rule.matchesName(normalized) {
			return false
		}
	}
	for _, rule := range snapshot.allow {
		if rule.matchesName(normalized) {
			return true
		}
	}
	if snapshot.allowAny {
		return true
	}
	for _, rule := range snapshot.allow {
		if rule.network != nil {
			return true
		}
	}
	return false
}

// RecordDNS remembers addresses returned for an authorized name. A bounded
// ten-minute cache is consulted by Allows for domain-only rules.
func (h *EgressPolicyHolder) RecordDNS(name string, addresses []net.IPAddr) {
	if h == nil || len(addresses) == 0 || !h.DNSAllowed(name) {
		return
	}
	normalized := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	now := time.Now()
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.snapshot == nil {
		return
	}
	if h.resolved == nil {
		h.resolved = make(map[string][]resolvedBinding)
	}
	if len(h.resolved) > 4096 {
		h.resolved = make(map[string][]resolvedBinding)
	}
	for _, address := range addresses {
		ip := address.IP
		if ip == nil {
			continue
		}
		key := ip.String()
		bindings := h.resolved[key][:0]
		for _, binding := range h.resolved[key] {
			if binding.expires.After(now) && binding.name != normalized {
				bindings = append(bindings, binding)
			}
		}
		bindings = append(bindings, resolvedBinding{name: normalized, expires: now.Add(10 * time.Minute)})
		if len(bindings) > 32 {
			bindings = bindings[len(bindings)-32:]
		}
		h.resolved[key] = bindings
	}
}

func (h *EgressPolicyHolder) resolvedNameLocked(protocol, address string, port uint16) (string, bool) {
	ip := net.ParseIP(address)
	if ip == nil {
		return "", false
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	bindings := h.resolved[ip.String()]
	if len(bindings) == 0 {
		return "", false
	}
	now := time.Now()
	snapshot := h.snapshot
	for i := len(bindings) - 1; i >= 0; i-- {
		binding := bindings[i]
		if !binding.expires.After(now) {
			continue
		}
		for _, rule := range snapshot.deny {
			if rule.matchesDomain(protocol, binding.name, port) {
				return "", false
			}
		}
		for _, rule := range snapshot.allow {
			if rule.matchesDomain(protocol, binding.name, port) {
				return binding.name, true
			}
		}
	}
	return "", false
}

func (h *EgressPolicyHolder) Close() error {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	audit := h.audit
	flows := h.flows
	h.flows = make(map[uint64]trackedEgressFlow)
	h.audit = nil
	h.snapshot = nil
	h.mu.Unlock()
	for _, flow := range flows {
		_ = flow.closer.Close()
	}
	return audit.close()
}
