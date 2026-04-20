package e2eutils

import (
	"fmt"
	"os"
	"os/exec"
	"time"

	log "github.com/sirupsen/logrus"
)

func waitProcessAsync(cmd *exec.Cmd) chan error {
	errCh := make(chan error)
	go func() {
		if err := cmd.Wait(); err != nil {
			errCh <- err
		}
		close(errCh)
	}()
	return errCh
}

type ReadyStatus int

const (
	Ready = iota
	ErrorRetry
	ErrorFailure
)

type readyFunc func() (ReadyStatus, error)

func waitProcessReady(cmd *exec.Cmd, ready readyFunc, retryDelay time.Duration, retryCount int) error {
	timeout := time.After(time.Duration(retryCount) * retryDelay)
	waitCh := waitProcessAsync(cmd)
	for {
		select {
		case err := <-waitCh:
			// process failed to start/errored out
			log.Errorf("error %v", err)
			if err != nil {
				return err
			}
			return fmt.Errorf("process exited unexpectedly")
		case <-time.After(retryDelay):
			status, err := ready()
			switch status {
			case Ready:
				return nil
			case ErrorRetry:
				break
			case ErrorFailure:
				return err
			}
		case <-timeout:
			return fmt.Errorf("process not ready after timeout")
		}
	}
}

type sshFunc func(cmd ...string) ([]byte, error)

func WaitSSH(cmd *exec.Cmd, sshExec sshFunc) error {
	sshCheck := func() (ReadyStatus, error) {
		_, err := sshExec("whoami")
		if err != nil {
			return ErrorRetry, err
		}
		return Ready, nil
	}

	return waitProcessReady(cmd, sshCheck, time.Second, 30)
}

func WaitGvproxy(cmd *exec.Cmd, sockets ...string) error {
	gvproxyCheck := func() (ReadyStatus, error) {
		for _, s := range sockets {
			if _, err := os.Stat(s); err != nil {
				if os.IsNotExist(err) {
					return ErrorRetry, err
				}
				return ErrorFailure, err
			}
		}
		return Ready, nil
	}

	return waitProcessReady(cmd, gvproxyCheck, 100*time.Millisecond, 50)
}
