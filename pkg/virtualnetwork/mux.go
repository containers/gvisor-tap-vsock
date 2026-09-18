package virtualnetwork

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"

	"github.com/containers/gvisor-tap-vsock/pkg/apilog"
	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/inetaf/tcpproxy"
	log "github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

// newServicesMux builds the raw ServeMux with service handlers.
// Use ServicesMux or Mux for the middleware-wrapped versions.
func (n *VirtualNetwork) newServicesMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/services/", http.StripPrefix("/services", n.servicesMux))
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(statsAsJSON(n.networkSwitch.Sent, n.networkSwitch.Received, n.stack.Stats())); err != nil {
			apilog.SetError(r, err)
		}
	})
	mux.HandleFunc("/cam", func(w http.ResponseWriter, r *http.Request) {
		cam := n.networkSwitch.CAM()
		apilog.AddField(r, "entries", len(cam))
		if err := json.NewEncoder(w).Encode(cam); err != nil {
			apilog.SetError(r, err)
		}
	})
	mux.HandleFunc("/leases", func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(n.ipPool.Leases()); err != nil {
			apilog.SetError(r, err)
		}
	})
	mux.HandleFunc("/tunnel", func(w http.ResponseWriter, r *http.Request) {
		ip := r.URL.Query().Get("ip")
		if ip == "" {
			http.Error(w, "ip is mandatory", http.StatusInternalServerError)
			return
		}
		port, err := strconv.ParseUint(r.URL.Query().Get("port"), 10, 16)
		if err != nil {
			apilog.AddField(r, "ip", ip)
			apilog.SetError(r, err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		port16 := uint16(port)

		apilog.AddField(r, "ip", ip)
		apilog.AddField(r, "port", port16)

		hj, ok := w.(http.Hijacker)
		if !ok {
			apilog.SetError(r, fmt.Errorf("webserver doesn't support hijacking"))
			http.Error(w, "webserver doesn't support hijacking", http.StatusInternalServerError)
			return
		}

		conn, bufrw, err := hj.Hijack()
		if err != nil {
			apilog.SetError(r, err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer conn.Close()

		if err := bufrw.Flush(); err != nil {
			apilog.SetError(r, err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if _, err := conn.Write([]byte(`OK`)); err != nil {
			apilog.SetError(r, err)
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
				apilog.SetError(r, dstDialErr)
			},
		}
		remote.HandleConn(conn)
	})
	return mux
}

// ServicesMux returns the services mux wrapped with audit logging middleware.
func (n *VirtualNetwork) ServicesMux() http.Handler {
	return apilog.Middleware(n.newServicesMux())
}

// Mux returns the full mux (services + connect) wrapped with audit logging middleware.
func (n *VirtualNetwork) Mux() http.Handler {
	mux := n.newServicesMux()
	mux.HandleFunc(types.ConnectPath, func(w http.ResponseWriter, r *http.Request) {
		apilog.AddField(r, "protocol", n.configuration.Protocol)
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "webserver doesn't support hijacking", http.StatusInternalServerError)
			return
		}
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			apilog.SetError(r, err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer conn.Close()

		if err := bufrw.Flush(); err != nil {
			apilog.SetError(r, err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if err := n.networkSwitch.Accept(context.Background(), conn, n.configuration.Protocol); err != nil {
			apilog.SetError(r, err)
		}
	})
	return apilog.Middleware(mux)
}
