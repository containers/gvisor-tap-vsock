//go:build windows
// +build windows

package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/containers/gvisor-tap-vsock/pkg/sshclient"
	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/containers/gvisor-tap-vsock/pkg/utils"
	"github.com/containers/winquit/pkg/winquit"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/windows/svc/eventlog"
)

const (
	ERR_BAD_ARGS = 0x000A
	WM_QUIT      = 0x12
)

var (
	stateDir string
	debug    bool
)

func main() {
	args := os.Args
	if len(args) > 1 {
		switch args[1] {
		case "-version":
			version := types.NewVersion("win-sshproxy")
			fmt.Println(version.String())
			os.Exit(0)
		case "-debug":
			debug = true
			args = args[2:]
		default:
			args = args[1:]
		}
	}

	if len(args) < 5 || (len(args)-2)%3 != 0 {
		alert("Usage: " + filepath.Base(os.Args[0]) + "(-debug) [name] [statedir] ([source] [dest] [identity])...  \n\nThis facilty proxies windows pipes and unix sockets over ssh using the specified identity.")
		os.Exit(ERR_BAD_ARGS)
	}

	log, err := setupLogging(args[0])
	if err != nil {
		os.Exit(1)
	}
	defer log.Close()

	stateDir = args[1]

	var sources, dests, identities []string
	for i := 2; i < len(args)-2; i += 3 {
		sources = append(sources, args[i])
		dests = append(dests, args[i+1])
		identities = append(identities, args[i+2])
	}

	ctx, cancel := context.WithCancel(context.Background())
	group, ctx := errgroup.WithContext(ctx)

	quit := make(chan bool, 1)
	// Wait for a WM_QUIT message to exit
	winquit.NotifyOnQuit(quit)
	go func() {
		<-quit
		cancel()
	}()

	// Save thread for legacy callers which use it to post a quit
	if _, err := saveThreadId(); err != nil {
		logrus.Errorf("Error saving thread id: " + err.Error())
	}

	logrus.Debug("Setting up proxies")
	setupProxies(ctx, group, sources, dests, identities)

	// Wait for cmopletion (cancellation) or error
	if err := group.Wait(); err != nil {
		logrus.Errorf("Error occured in execution group: " + err.Error())
		os.Exit(1)
	}
}

func setupLogging(name string) (*eventlog.Log, error) {
	// Reuse the Built-in .NET Runtime Source so that we do not
	// have to provide a messaage table and modify the system
	// event configuration
	log, err := eventlog.Open(".NET Runtime")
	if err != nil {
		return nil, err
	}

	logrus.AddHook(NewEventHook(log, name))
	if debug {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}

	return log, nil
}

func setupProxies(ctx context.Context, g *errgroup.Group, sources []string, dests []string, identities []string) error {
	for i := 0; i < len(sources); i++ {
		var (
			src  *url.URL
			dest *url.URL
			err  error
		)
		if strings.Contains(sources[i], "://") {
			src, err = url.Parse(sources[i])
			if err != nil {
				return err
			}
		} else {
			src = &url.URL{
				Scheme: "unix",
				Path:   sources[i],
			}
		}

		dest, err = url.Parse(dests[i])
		if err != nil {
			return err
		}
		j := i
		g.Go(func() error {
			forward, err := sshclient.CreateSSHForward(ctx, src, dest, identities[j], nil)
			if err != nil {
				return err
			}
			go func() {
				<-ctx.Done()
				// Abort pending accepts
				forward.Close()
			}()
		loop:
			for {
				select {
				case <-ctx.Done():
					break loop
				default:
					// proceed
				}
				err := forward.AcceptAndTunnel(ctx)
				if err != nil {
					logrus.Debugf("Error occurred handling ssh forwarded connection: %q", err)
				}
			}
			return nil
		})
	}

	return nil
}

func saveThreadId() (uint32, error) {
	path := filepath.Join(stateDir, "win-sshproxy.tid")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0644)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	tid, err := getThreadId()
	if err != nil {
		return 0, err
	}

	fmt.Fprintf(file, "%d:%d\n", os.Getpid(), tid)
	return tid, nil
}

func getThreadId() (uint32, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	getTid := func() (uint32, error) {
		tid := winquit.GetCurrentMessageLoopThreadId()
		if tid != 0 {
			return tid, nil
		}
		return 0, fmt.Errorf("failed to get thread ID")
	}

	return utils.Retry(ctx, getTid, "Waiting for message loop thread id")
}

// Creates an "error" style pop-up window
func alert(caption string) int {
	// Error box style
	format := 0x10

	user32 := syscall.NewLazyDLL("user32.dll")
	captionPtr, _ := syscall.UTF16PtrFromString(caption)
	titlePtr, _ := syscall.UTF16PtrFromString("winpath")
	ret, _, _ := user32.NewProc("MessageBoxW").Call(
		uintptr(0),
		uintptr(unsafe.Pointer(captionPtr)),
		uintptr(unsafe.Pointer(titlePtr)),
		uintptr(format))

	return int(ret)
}
