package stdio

import (
	"errors"
	"strconv"
	"syscall"
	"testing"
)

func TestCloseReapsChild(t *testing.T) {
	conn, err := Dial("true")
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(conn.RemoteAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	// Once reaped, the child can no longer be waited for.
	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &ws, syscall.WNOHANG, nil); !errors.Is(err, syscall.ECHILD) {
		t.Fatalf("child %d still waitable after Close (zombie), wait4: %v", pid, err)
	}
}
