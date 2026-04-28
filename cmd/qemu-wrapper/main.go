package main

import (
	"log"
	"net"
	"os"
	"os/exec"
)

func main() {
	conn, err := net.Dial("unix", os.Args[1]) // #nosec G704 - internal utility with controlled socket path
	if err != nil {
		log.Fatal(err)
	}
	fd, err := conn.(*net.UnixConn).File()
	if err != nil {
		log.Fatal(err)
	}
	cmd := exec.Command(os.Args[2], os.Args[3:]...) // #nosec G204 G702 - internal utility with controlled arguments
	cmd.ExtraFiles = append(cmd.ExtraFiles, fd)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatal(err)
	}
}
