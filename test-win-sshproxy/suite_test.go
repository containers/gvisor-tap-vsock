// +build windows

package e2e

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const (
	WM_QUIT = 0x12
)

var (
	tmpDir      string
	binDir      string
	keyFile     string
	winSshProxy string
	tidFile     string
)

func TestSuite(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "win-sshproxy suite")
}

func init() {
	flag.StringVar(&tmpDir, "tmpDir", "../tmp", "temporary working directory")
	flag.StringVar(&binDir, "bin", "../bin", "directory with compiled binaries")
	_ = os.MkdirAll(tmpDir, 0755)
	keyFile = filepath.Join(tmpDir, "id.key")
	_ = os.WriteFile(keyFile, []byte(fakeHostKey), 0600)
	winSshProxy = filepath.Join(binDir, "win-sshproxy.exe")
	tidFile = filepath.Join(tmpDir, "win-sshproxy.tid")
}

var _ = BeforeSuite(func() {
	startMockServer()
})

var _ = AfterSuite(func() {
	stopMockServer()
})

func startProxy() error {
	os.Remove(tidFile)
	cmd := exec.Command(winSshProxy, "-debug", "test", tmpDir, "npipe:////./pipe/fake_docker_engine", "ssh://localhost:2134/run/podman/podman.sock", keyFile)
	return cmd.Start()
}

func readTid() (uint32, uint32, error) {
	contents, err := os.ReadFile(tidFile)
	if err != nil {
		return 0, 0, err
	}

	var pid, tid uint32
	fmt.Sscanf(string(contents), "%d:%d", &pid, &tid)
	return pid, tid, nil
}

func sendQuit(tid uint32) {
	user32 := syscall.NewLazyDLL("user32.dll")
	postMessage := user32.NewProc("PostThreadMessageW")
	postMessage.Call(uintptr(tid), WM_QUIT, 0, 0)
}

func stopProxy(noKill bool) error {
	pid, tid, err := readTid()
	if err != nil {
		return err
	}

	proc, err := os.FindProcess(int(pid))
	if err != nil {
		return err
	}
	sendQuit(tid)
	state := waitTimeout(proc, 20*time.Second)
	if state == nil || !state.Exited() {
		if noKill {
			return fmt.Errorf("proxy did not exit on request")
		}
		_ = proc.Kill()
		state = waitTimeout(proc, 20*time.Second)
	}

	if state == nil || !state.Exited() {
		return fmt.Errorf("Stop proxy failed: %d", pid)
	}

	_ = os.Remove(tidFile)
	return nil
}

func waitTimeout(proc *os.Process, timeout time.Duration) *os.ProcessState {
	return doTimeout(func(complete chan *os.ProcessState) {
		state, _ := proc.Wait()
		complete <- state
	}, timeout)
}

func doTimeout(action func(complete chan *os.ProcessState), timeout time.Duration) *os.ProcessState {
	complete := make(chan *os.ProcessState)

	go action(complete)
	select {
	case <-time.After(timeout):
		return nil

	case state := <-complete:
		return state
	}
}
