package main

import (
	"fmt"
	"net"
	"os"
	"path"
)

func listen() (net.Listener, error) {
	path := path.Join(os.Getenv("VM_DIRECTORY"), fmt.Sprintf("00000002.%08x", 1024))
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return net.ListenUnix("unix", &net.UnixAddr{
		Name: path,
		Net:  "unix",
	})
}
