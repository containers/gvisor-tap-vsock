package transport

import (
	"net"
	"net/url"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/go-winio/pkg/guid"
)

const DefaultURL = "vsock://00000400-FACB-11E6-BD58-64006A7986D3"

func listenURL(parsed *url.URL) (net.Listener, error) {
	switch parsed.Scheme {
	case "vsock":
		svcid, err := guid.FromString(parsed.Hostname())
		if err != nil {
			return nil, err
		}
		return winio.ListenHvsock(&winio.HvsockAddr{
			VMID:      winio.HvsockGUIDWildcard(),
			ServiceID: svcid,
		})
	default:
		return defaultListenURL(parsed)
	}
}
