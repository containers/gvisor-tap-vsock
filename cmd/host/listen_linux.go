package main

import (
	"net"

	mdlayhervsock "github.com/mdlayher/vsock"
)

func listen() (net.Listener, error) {
	return mdlayhervsock.Listen(1024)
}
