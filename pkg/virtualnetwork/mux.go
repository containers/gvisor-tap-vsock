package virtualnetwork

import (
	"context"
	"encoding/json"
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

func (n *VirtualNetwork) ServicesMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/services/", http.StripPrefix("/services", n.servicesMux))
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(statsAsJSON(n.networkSwitch.Sent, n.networkSwitch.Received, n.stack.Stats()))
		apilog.LogEvent(r, "/stats", "success", nil)
	})
	mux.HandleFunc("/cam", func(w http.ResponseWriter, r *http.Request) {
		cam := n.networkSwitch.CAM()
		_ = json.NewEncoder(w).Encode(cam)
		apilog.LogEvent(r, "/cam", "success", log.Fields{
			"entries": len(cam),
		})
	})
	mux.HandleFunc("/leases", func(w http.ResponseWriter, r *http.Request) {
		apilog.LogEvent(r, "/leases", "success", nil)
		_ = json.NewEncoder(w).Encode(n.ipPool.Leases())
	})
	mux.HandleFunc("/tunnel", func(w http.ResponseWriter, r *http.Request) {
		ip := r.URL.Query().Get("ip")
		if ip == "" {
			apilog.LogEvent(r, "/tunnel", "error", log.Fields{
				"error": "ip is mandatory",
			})
			http.Error(w, "ip is mandatory", http.StatusInternalServerError)
			return
		}
		port, err := strconv.ParseUint(r.URL.Query().Get("port"), 10, 16)
		if err != nil {
			apilog.LogEvent(r, "/tunnel", "error", log.Fields{
				"ip":    ip,
				"error": err.Error(),
			})
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		port16 := uint16(port)

		hj, ok := w.(http.Hijacker)
		if !ok {
			apilog.LogEvent(r, "/tunnel", "error", log.Fields{
				"ip":    ip,
				"port":  port16,
				"error": "webserver doesn't support hijacking",
			})
			http.Error(w, "webserver doesn't support hijacking", http.StatusInternalServerError)
			return
		}

		conn, bufrw, err := hj.Hijack()
		if err != nil {
			apilog.LogEvent(r, "/tunnel", "error", log.Fields{
				"ip":    ip,
				"port":  port16,
				"error": err.Error(),
			})
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer conn.Close()

		if err := bufrw.Flush(); err != nil {
			apilog.LogEvent(r, "/tunnel", "error", log.Fields{
				"ip":    ip,
				"port":  port16,
				"error": err.Error(),
			})
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if _, err := conn.Write([]byte(`OK`)); err != nil {
			apilog.LogEvent(r, "/tunnel", "error", log.Fields{
				"ip":    ip,
				"port":  port16,
				"error": err.Error(),
			})
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		apilog.LogEvent(r, "/tunnel", "success", log.Fields{
			"ip":   ip,
			"port": port16,
		})

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

func (n *VirtualNetwork) Mux() *http.ServeMux {
	mux := n.ServicesMux()
	mux.HandleFunc(types.ConnectPath, func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			apilog.LogEvent(r, types.ConnectPath, "error", log.Fields{
				"protocol": n.configuration.Protocol,
				"error":    "webserver doesn't support hijacking",
			})
			http.Error(w, "webserver doesn't support hijacking", http.StatusInternalServerError)
			return
		}
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			apilog.LogEvent(r, types.ConnectPath, "error", log.Fields{
				"protocol": n.configuration.Protocol,
				"error":    err.Error(),
			})
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer conn.Close()

		if err := bufrw.Flush(); err != nil {
			apilog.LogEvent(r, types.ConnectPath, "error", log.Fields{
				"protocol": n.configuration.Protocol,
				"error":    err.Error(),
			})
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		apilog.LogEvent(r, types.ConnectPath, "success", log.Fields{
			"protocol": n.configuration.Protocol,
		})
		if err := n.networkSwitch.Accept(context.Background(), conn, n.configuration.Protocol); err != nil {
			apilog.LogEvent(r, types.ConnectPath, "error", log.Fields{
				"protocol": n.configuration.Protocol,
				"error":    err.Error(),
			})
		}
	})
	return mux
}
