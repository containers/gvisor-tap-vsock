package main

import (
	"fmt"
	"net"

	"github.com/linuxkit/virtsock/pkg/hvsock"
)

func listen() (net.Listener, error) {
	svcid, err := hvsock.GUIDFromString(fmt.Sprintf("%08x-FACB-11E6-BD58-64006A7986D3", 1024))
	if err != nil {
		return nil, err
	}
	return hvsock.Listen(hvsock.Addr{
		VMID:      hvsock.GUIDWildcard,
		ServiceID: svcid,
	})
}
