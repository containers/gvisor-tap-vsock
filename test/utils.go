package e2e

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
)

func Exec(cmd *exec.Cmd, timeout <-chan time.Time) (string, string, error) {
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	log.Infof("Running '%s %s'", cmd.Path, strings.Join(cmd.Args[1:], " ")) // skip arg[0] as it is printed separately
	if err := cmd.Start(); err != nil {
		return "", "", fmt.Errorf("error starting %v:\nCommand stdout:\n%v\nstderr:\n%v\nerror:\n%v", cmd, cmd.Stdout, cmd.Stderr, err)
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- cmd.Wait()
	}()
	select {
	case err := <-errCh:
		if err != nil {
			var rc = 127
			if ee, ok := err.(*exec.ExitError); ok {
				rc = int(ee.Sys().(syscall.WaitStatus).ExitStatus())
				log.Infof("rc: %d", rc)
			}
			return stdout.String(), stderr.String(), CodeExitError{
				Err:  fmt.Errorf("error running %v:\nCommand stdout:\n%v\nstderr:\n%v\nerror:\n%v", cmd, cmd.Stdout, cmd.Stderr, err),
				Code: rc,
			}
		}
	case <-timeout:
		_ = cmd.Process.Kill()
		return "", "", fmt.Errorf("timed out waiting for command %v:\nCommand stdout:\n%v\nstderr:\n%v", cmd, cmd.Stdout, cmd.Stderr)
	}
	log.Infof("stderr: %q", stderr.String())
	log.Infof("stdout: %q", stdout.String())
	return stdout.String(), stderr.String(), nil
}

// CodeExitError is an implementation of ExitError consisting of an error object
// and an exit code (the upper bits of os.exec.ExitStatus).
type CodeExitError struct {
	Err  error
	Code int
}

func (e CodeExitError) Error() string {
	return e.Err.Error()
}

func (e CodeExitError) String() string {
	return e.Err.Error()
}

func (e CodeExitError) Exited() bool {
	return true
}

func (e CodeExitError) ExitStatus() int {
	return e.Code
}
