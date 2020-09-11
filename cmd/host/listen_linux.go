package main

import (
	"errors"
	"net"
	"net/url"
	"strconv"

	mdlayhervsock "github.com/mdlayher/vsock"
)

const defaultURL = "vsock://:1024"

func listen() (net.Listener, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	switch parsed.Scheme {
	case "vsock":
		port, err := strconv.Atoi(parsed.Port())
		if err != nil {
			return nil, err
		}
		return mdlayhervsock.Listen(uint32(port))
	case "unix":
		return net.Listen("unix", parsed.Path)
	default:
		return nil, errors.New("unexpected scheme")
	}
}
