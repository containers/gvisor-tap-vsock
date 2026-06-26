# Filter REST API Documentation

The Filter API provides runtime observability and control over outbound network filtering in gvisor-tap-vsock.

## Base Path

All endpoints are available under `/services/filter/`

## Authentication

Currently no authentication is required. Access control should be managed at the socket level.

## Endpoints

### Connection Observability

#### `GET /services/filter/connections`

Lists all tracked connections (both allowed and blocked) with aggregated statistics.

**Response:**
```json
{
  "connections": [
    {
      "protocol": "tcp",
      "destination_ip": "142.250.80.46",
      "destination_port": 443,
      "sni": "www.example.com",
      "domain": "www.example.com",
      "status": "allowed",
      "count": 42,
      "first_seen": "2026-04-22T10:30:00Z",
      "last_seen": "2026-04-22T11:45:00Z"
    }
  ]
}
```

The `domain` field is populated from the TLS SNI (for HTTPS connections) or from the DNS cache (for plain HTTP connections where the VM resolved the domain through gvisor-tap-vsock's DNS handler). The `sni` field is kept for backward compatibility and contains the raw TLS Server Name Indication value.
```

#### `GET /services/filter/connections/blocked`

Lists only blocked connections.

#### `GET /services/filter/connections/allowed`

Lists only allowed connections.

### DNS Observability

#### `GET /services/filter/dns/queries`

Lists tracked DNS queries with aggregated counts.

**Response:**
```json
{
  "queries": [
    {
      "domain": "example.com",
      "status": "allowed",
      "count": 15,
      "first_seen": "2026-04-22T10:00:00Z",
      "last_seen": "2026-04-22T11:00:00Z"
    }
  ]
}
```

#### `GET /services/filter/dns/blocked`

Lists only blocked DNS queries.

### Allowlist Management

The allowlist supports two sources: **dynamic** (managed via REST API using plain domain names) and **config** (regex patterns from YAML config file). Allowing a domain automatically includes all its subdomains — for example, allowing `github.com` also allows `api.github.com`, `raw.github.com`, etc.

#### `GET /services/filter/allowlist`

Get current allowlist entries. Dynamic entries are shown as domain names; config entries are shown as regex patterns.

**Response:**
```json
{
  "domains": [
    {
      "domain": "github.com",
      "added_at": "2026-04-22T10:30:00Z"
    }
  ],
  "config_patterns": [
    "^.*\\.example\\.com$"
  ]
}
```

#### `POST /services/filter/allowlist`

Add a domain to the dynamic allowlist at runtime. The domain and all its subdomains will be allowed.

**Request:**
```json
{
  "domain": "trusted.org"
}
```

**Response:**
```json
{
  "success": true,
  "domain": "trusted.org"
}
```

#### `DELETE /services/filter/allowlist`

Remove a domain from the dynamic allowlist. Config-sourced patterns cannot be removed via the API.

**Request:**
```json
{
  "domain": "trusted.org"
}
```

**Response:**
```json
{
  "success": true,
  "removed": true
}
```

**Not found:**
```json
{
  "success": false,
  "removed": false,
  "note": "Domain not found in dynamic allowlist"
}
```

### Blocklist Management

The blocklist supports two blocking modes: **IP-based** (block a specific IP:port:protocol) and **domain-based** (block all traffic to a domain and its subdomains, regardless of port or protocol). Blocking `example.com` automatically blocks `www.example.com`, `mail.example.com`, etc. Domain-based blocking works by looking up the IP→domain mapping from the DNS cache — the VM must have resolved the domain through gvisor-tap-vsock's DNS handler for domain blocking to take effect.

#### `GET /services/filter/blocklist`

Get current dynamic blocklist entries (both IP-based and domain-based).

**Response:**
```json
{
  "entries": [
    {
      "protocol": "tcp",
      "ip": "10.0.0.5",
      "port": 443,
      "added_at": "2026-04-22T11:00:00Z",
      "reason": "user blocked"
    }
  ],
  "domain_entries": [
    {
      "domain": "evil.com",
      "added_at": "2026-04-22T11:00:00Z",
      "reason": "malicious"
    }
  ]
}
```

#### `POST /services/filter/blocklist`

Block by IP:port:protocol or by domain name. Blocking a domain automatically includes all its subdomains.

**IP-based request:**
```json
{
  "protocol": "tcp",
  "ip": "10.0.0.5",
  "port": 443,
  "reason": "suspicious activity"
}
```

**Domain-based request (blocks evil.com, www.evil.com, etc.):**
```json
{
  "domain": "evil.com",
  "reason": "malicious domain"
}
```

**Response:**
```json
{
  "success": true,
  "blocked": true
}
```

#### `DELETE /services/filter/blocklist`

Remove an entry from the blocklist (by IP:port or by domain).

**IP-based request:**
```json
{
  "protocol": "tcp",
  "ip": "10.0.0.5",
  "port": 443
}
```

**Domain-based request:**
```json
{
  "domain": "evil.com"
}
```

**Response:**
```json
{
  "success": true,
  "removed": true
}
```

### Statistics

#### `GET /services/filter/stats`

Overall filtering statistics.

**Response:**
```json
{
  "total_connections": 1234,
  "blocked_connections": 56,
  "allowed_connections": 1178,
  "total_dns_queries": 890,
  "blocked_dns_queries": 23,
  "uptime_seconds": 3600,
  "allowlist_patterns": 5,
  "blocklist_entries": 2
}
```

### History Management

#### `DELETE /services/filter/history`

Clear all tracked connection and DNS history (does not clear allowlist/blocklist).

**Response:**
```json
{
  "success": true,
  "cleared": {
    "connections": 1234,
    "dns_queries": 890
  }
}
```

### Real-Time Monitoring

#### `GET /services/filter/events`

Server-Sent Events (SSE) stream for real-time filtering decisions.

**Event Types:**
- `connection_blocked` - Connection blocked by allowlist or dynamic blocklist
- `connection_allowed` - Connection allowed
- `dns_blocked` - DNS query blocked
- `dns_allowed` - DNS query allowed
- `allowlist_updated` - Allowlist pattern added/removed
- `blocklist_updated` - Blocklist entry added/removed

**Event Format:**
```
event: connection_blocked
data: {"protocol":"tcp","ip":"10.0.0.5","port":443,"sni":"evil.com","reason":"not in allowlist"}

event: dns_allowed
data: {"domain":"example.com","status":"allowed"}

event: allowlist_updated
data: {"action":"added","domain":"trusted.org"}
```

**Usage with curl:**
```bash
curl --unix-socket /tmp/gvproxy-services.sock \
  http://localhost/services/filter/events
```

**Usage with JavaScript:**
```javascript
const eventSource = new EventSource('http://localhost/services/filter/events');

eventSource.addEventListener('connection_blocked', (e) => {
  const data = JSON.parse(e.data);
  console.log('Connection blocked:', data);
});

eventSource.addEventListener('dns_blocked', (e) => {
  const data = JSON.parse(e.data);
  console.log('DNS blocked:', data);
});
```

## Usage Examples

### Using curl with Unix socket

```bash
# View statistics
curl --unix-socket /tmp/gvproxy-services.sock \
  http://localhost/services/filter/stats | jq

# View blocked connections
curl --unix-socket /tmp/gvproxy-services.sock \
  http://localhost/services/filter/connections/blocked | jq

# Add domain to allowlist (allows domain + all subdomains)
curl --unix-socket /tmp/gvproxy-services.sock -X POST \
  http://localhost/services/filter/allowlist \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com"}'

# Block specific connection by IP
curl --unix-socket /tmp/gvproxy-services.sock -X POST \
  http://localhost/services/filter/blocklist \
  -H "Content-Type: application/json" \
  -d '{"protocol":"tcp","ip":"10.0.0.5","port":443,"reason":"suspicious"}'

# Block by domain (blocks evil.com and all subdomains, all ports/protocols)
curl --unix-socket /tmp/gvproxy-services.sock -X POST \
  http://localhost/services/filter/blocklist \
  -H "Content-Type: application/json" \
  -d '{"domain":"evil.com","reason":"malicious"}'

# Watch events in real-time
curl --unix-socket /tmp/gvproxy-services.sock \
  http://localhost/services/filter/events
```

### Testing Script

A test script is provided: `scripts/test-filter-api.sh`

```bash
chmod +x scripts/test-filter-api.sh
./scripts/test-filter-api.sh
```

## Configuration

The filter API is automatically enabled when gvproxy starts. Outbound filtering
is configured via a YAML config file passed with `--config`:

```yaml
# gvproxy-config.yaml
listen:
  - unix:///tmp/gvproxy.sock
services: unix:///tmp/gvproxy-services.sock
stack:
  # Allowlist mode: block everything except matching domains
  outboundAllow:
    - "^.*\\.github\\.com$"
    - "^registry\\.fedoraproject\\.org$"
  # Optional: cap the number of tracked connection/DNS records (default: 10000)
  maxFilterHistory: 5000
```

```bash
./bin/gvproxy --config gvproxy-config.yaml
```

To block all outbound traffic (only gateway traffic allowed):

```yaml
stack:
  blockAllOutbound: true
```

Then use the API to dynamically manage filtering at runtime.

## Integration Examples

### Python

```python
import requests
import json
from requests_unixsocket import Session

session = Session()
socket_url = 'http+unix://%2Ftmp%2Fgvproxy-services.sock'

# Get statistics
response = session.get(f'{socket_url}/services/filter/stats')
stats = response.json()
print(f"Total connections: {stats['total_connections']}")

# Add to allowlist (allows domain + all subdomains)
response = session.post(
    f'{socket_url}/services/filter/allowlist',
    json={'domain': 'example.com'}
)
print(response.json())

# Block connection
response = session.post(
    f'{socket_url}/services/filter/blocklist',
    json={
        'protocol': 'tcp',
        'ip': '10.0.0.5',
        'port': 443,
        'reason': 'blocked by policy'
    }
)
print(response.json())
```

### Go

```go
package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net"
    "net/http"
)

func main() {
    client := &http.Client{
        Transport: &http.Transport{
            Dial: func(proto, addr string) (net.Conn, error) {
                return net.Dial("unix", "/tmp/gvproxy-services.sock")
            },
        },
    }

    // Get stats
    resp, _ := client.Get("http://localhost/services/filter/stats")
    defer resp.Body.Close()
    
    var stats map[string]interface{}
    json.NewDecoder(resp.Body).Decode(&stats)
    fmt.Printf("Total connections: %v\n", stats["total_connections"])

    // Add to allowlist (allows domain + all subdomains)
    payload := map[string]string{"domain": "example.com"}
    body, _ := json.Marshal(payload)
    resp, _ = client.Post(
        "http://localhost/services/filter/allowlist",
        "application/json",
        bytes.NewBuffer(body),
    )
    defer resp.Body.Close()
}
```

## Notes

- **Memory Management**: Connection and DNS history is capped by `maxFilterHistory` (default 10000 entries per map). When the limit is reached the oldest entry is evicted automatically. History can also be cleared manually with `DELETE /services/filter/history`
- **Domain Matching**: Both allowlist and blocklist use domain names. Adding `example.com` automatically matches `example.com` and all subdomains (`www.example.com`, `api.example.com`, etc.)
- **Config vs Dynamic**: The YAML config file uses regex patterns for the allowlist (`outboundAllow`). The REST API uses plain domain names. Config-sourced patterns cannot be removed via the API.
- **SSE Buffering**: SSE subscriber channels are buffered. Slow consumers may miss events.
- **Thread Safety**: All API operations are thread-safe
