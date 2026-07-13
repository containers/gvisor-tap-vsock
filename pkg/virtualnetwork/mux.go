package virtualnetwork

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"

	"github.com/containers/gvisor-tap-vsock/pkg/services/forwarder"
	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/inetaf/tcpproxy"
	log "github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

// Mux returns the full API handler, including the /connect endpoint.
// Used by the -listen flag for the main control plane API.
func (n *VirtualNetwork) Mux() *http.ServeMux {
	mux := n.ServicesMux()

	// Hypervisor connection (packet stream)
	mux.HandleFunc(types.ConnectPath, func(w http.ResponseWriter, _ *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "webserver doesn't support hijacking", http.StatusInternalServerError)
			return
		}
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer conn.Close()

		if err := bufrw.Flush(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		_ = n.networkSwitch.Accept(context.Background(), conn, n.configuration.Protocol)
	})

	return mux
}

// ServicesMux returns the API handler without the /connect endpoint.
// Used by the -services flag.
func (n *VirtualNetwork) ServicesMux() *http.ServeMux {
	mux := http.NewServeMux()

	// Port Forwarding
	mux.HandleFunc("/services/forwarder/all", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(n.forwarder.List())
	})
	mux.HandleFunc("/services/forwarder/expose", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "post only", http.StatusBadRequest)
			return
		}
		var req types.ExposeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.Protocol == "" {
			req.Protocol = types.TCP
		}

		remoteAddr := req.Remote
		if req.Protocol != types.UNIX && req.Protocol != types.NPIPE {
			var err error
			remoteAddr, err = forwarder.Remote(req, r.RemoteAddr)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}

		if err := n.forwarder.Expose(req.Protocol, req.Local, remoteAddr); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/services/forwarder/unexpose", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "post only", http.StatusBadRequest)
			return
		}
		var req types.UnexposeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.Protocol == "" {
			req.Protocol = types.TCP
		}
		if err := n.forwarder.Unexpose(req.Protocol, req.Local); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	// DNS Management
	mux.HandleFunc("/services/dns/all", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(n.dnsServer.Zones())
	})
	mux.HandleFunc("/services/dns/add", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "post only", http.StatusBadRequest)
			return
		}
		var req types.Zone
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		n.dnsServer.AddZone(req)
		w.WriteHeader(http.StatusOK)
	})

	// DHCP
	mux.HandleFunc("/services/dhcp/leases", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(n.dhcpServer.Leases())
	})

	// Network Information
	mux.HandleFunc("/stats", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(statsAsJSON(n.networkSwitch.Sent, n.networkSwitch.Received, n.stack.Stats()))
	})
	mux.HandleFunc("/cam", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(n.networkSwitch.CAM())
	})
	mux.HandleFunc("/leases", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(n.ipPool.Leases())
	})

	// Tunneling
	mux.HandleFunc("/tunnel", func(w http.ResponseWriter, r *http.Request) {
		ip := r.URL.Query().Get("ip")
		if ip == "" {
			http.Error(w, "ip is mandatory", http.StatusInternalServerError)
			return
		}
		port, err := strconv.ParseUint(r.URL.Query().Get("port"), 10, 16)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		port16 := uint16(port)

		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "webserver doesn't support hijacking", http.StatusInternalServerError)
			return
		}

		conn, bufrw, err := hj.Hijack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer conn.Close()

		if err := bufrw.Flush(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if _, err := conn.Write([]byte(`OK`)); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		remote := tcpproxy.DialProxy{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return gonet.DialContextTCP(ctx, n.stack, tcpip.FullAddress{
					NIC:  1,
					Addr: tcpip.AddrFrom4Slice(net.ParseIP(ip).To4()),
					Port: port16,
				}, ipv4.ProtocolNumber)
			},
			OnDialError: func(_ net.Conn, dstDialErr error) {
				log.Errorf("cannot dial: %v", dstDialErr)
			},
		}
		remote.HandleConn(conn)
	})

	return mux
}

// GatewayMux returns the restricted API handler for the VM-facing gateway.
// Only exposes port forwarding endpoints. Unix/npipe protocols are blocked
// unless allowAllProtocols is true.
func (n *VirtualNetwork) GatewayMux(allowAllProtocols bool) *http.ServeMux {
	mux := http.NewServeMux()
	vnMux := n.Mux()

	mux.Handle("/services/forwarder/all", vnMux)
	if allowAllProtocols {
		mux.Handle("/services/forwarder/expose", vnMux)
	} else {
		mux.Handle("/services/forwarder/expose", GatewayProtocolFilter(vnMux))
	}
	mux.Handle("/services/forwarder/unexpose", vnMux)

	return mux
}

// GatewayProtocolFilter blocks unix and npipe protocols on the gateway API.
func GatewayProtocolFilter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Protocol string `json:"protocol"`
		}

		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		r.Body.Close()

		if err := json.Unmarshal(bodyBytes, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if req.Protocol == "unix" || req.Protocol == "npipe" {
			log.Warnf("blocked %s protocol on gateway API", req.Protocol)
			http.Error(w, "unix and npipe protocols are not allowed on the gateway API", http.StatusForbidden)
			return
		}

		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		next.ServeHTTP(w, r)
	})
}
