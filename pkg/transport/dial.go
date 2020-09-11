package transport

import (
	"net"
	"net/url"
	"strconv"

	mdlayhervsock "github.com/mdlayher/vsock"
	"github.com/pkg/errors"
)

func Dial(endpoint string) (net.Conn, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	switch parsed.Scheme {
	case "vsock":
		contextID, err := strconv.Atoi(parsed.Hostname())
		if err != nil {
			return nil, err
		}
		port, err := strconv.Atoi(parsed.Port())
		if err != nil {
			return nil, err
		}
		return mdlayhervsock.Dial(uint32(contextID), uint32(port))
	case "unix":
		return net.Dial("unix", parsed.Path)
	default:
		return nil, errors.New("unexpected scheme")
	}
}
