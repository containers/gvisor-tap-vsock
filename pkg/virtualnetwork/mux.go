package virtualnetwork

import (
	"net/http"

	"github.com/containers/gvisor-tap-vsock/pkg/apilog"
	"github.com/containers/gvisor-tap-vsock/pkg/tokenauth"
	"github.com/containers/gvisor-tap-vsock/pkg/types"
)

// rawServicesMux builds the raw ServeMux with service handlers.
// Use ServicesMux or Mux for the middleware-wrapped versions.
func (n *VirtualNetwork) rawServicesMux() *http.ServeMux {
	mux := http.NewServeMux()

	// Port Forwarding
	mux.HandleFunc("/services/forwarder/all", n.handleForwarderList)
	mux.HandleFunc("/services/forwarder/expose", n.handleForwarderExpose)
	mux.HandleFunc("/services/forwarder/unexpose", n.handleForwarderUnexpose)

	// DNS
	mux.HandleFunc("/services/dns/all", n.handleDNSList)
	mux.HandleFunc("/services/dns/add", n.handleDNSAdd)

	// DHCP (available at both paths for compatibility)
	mux.HandleFunc("/services/dhcp/leases", n.handleLeases)
	mux.HandleFunc("/leases", n.handleLeases)

	// Network Information
	mux.HandleFunc("/stats", n.handleStats)
	mux.HandleFunc("/cam", n.handleCAM)

	// Tunneling
	mux.HandleFunc("/tunnel", n.handleTunnel)

	return mux
}

// ServicesMux returns the services mux wrapped with audit logging middleware.
func (n *VirtualNetwork) ServicesMux() http.Handler {
	return apilog.Middleware(n.rawServicesMux())
}

// Mux returns the full mux (services + connect) wrapped with audit logging middleware.
func (n *VirtualNetwork) Mux() http.Handler {
	mux := n.rawServicesMux()
	mux.HandleFunc(types.ConnectPath, n.handleConnect)
	return apilog.Middleware(mux)
}

// GatewayMux returns a mux for the gateway endpoint (accessible from the VM),
// wrapped with audit logging middleware. It only exposes the forwarder endpoints,
// optionally wrapped with token authentication if SetAPIToken() was called with
// a non-empty token.
func (n *VirtualNetwork) GatewayMux() http.Handler {
	gatewayMux := http.NewServeMux()

	// Only expose the forwarder endpoints
	gatewayMux.HandleFunc("/services/forwarder/all", n.handleForwarderList)
	gatewayMux.HandleFunc("/services/forwarder/expose", n.handleForwarderExpose)
	gatewayMux.HandleFunc("/services/forwarder/unexpose", n.handleForwarderUnexpose)

	handler := http.Handler(gatewayMux)

	// If a token is configured, wrap it with authentication middleware
	if n.apiToken != "" {
		handler = tokenauth.BearerAuthMiddleware(n.apiToken)(handler)
	}

	return apilog.Middleware(handler)
}
