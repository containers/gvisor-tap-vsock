package main

import (
	"log"
	"net"
	"os"
	"os/exec"
)

func main() {
	conn, err := net.Dial("unix", os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	fd, err := conn.(*net.UnixConn).File()
	if err != nil {
		log.Fatal(err)
	}
	cmd := exec.Command(os.Args[2], os.Args[3:]...) // #nosec G204
	cmd.ExtraFiles = append(cmd.ExtraFiles, fd)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatal(err)
	}
}
