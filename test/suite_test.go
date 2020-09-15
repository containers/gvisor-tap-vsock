package e2e

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

func TestSuite(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "gvisor-tap-vsock suite")
}

const sock = "/tmp/mysock"

var (
	binDir             string
	changeDefaultRoute bool
	host               *exec.Cmd
	client             *exec.Cmd
)

func init() {
	flag.StringVar(&binDir, "bin", "../bin", "directory with compiled binaries")
	flag.BoolVar(&changeDefaultRoute, "change-default-route", false, "change the default route to use this interface")
}

var _ = BeforeSuite(func() {
	_ = os.Remove(sock)
	// #nosec
	host = exec.Command(filepath.Join(binDir, "host"), fmt.Sprintf("--listen=unix://%s", sock))
	host.Stderr = os.Stderr
	host.Stdout = os.Stdout
	Expect(host.Start()).Should(Succeed())
	go func() {
		if err := host.Wait(); err != nil {
			log.Error(err)
		}
	}()

	for {
		_, err := os.Stat(sock)
		if os.IsNotExist(err) {
			log.Info("waiting for socket")
			time.Sleep(100 * time.Millisecond)
			continue
		}
		break
	}

	// #nosec
	client = exec.Command("sudo", filepath.Join(binDir, "vm"), fmt.Sprintf("--url=unix://%s", sock), fmt.Sprintf("--change-default-route=%v", changeDefaultRoute))
	client.Stderr = os.Stderr
	client.Stdout = os.Stdout
	Expect(client.Start()).Should(Succeed())
	go func() {
		if err := client.Wait(); err != nil {
			log.Error(err)
		}
	}()

	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", sock)
			},
		},
	}

	for {
		cam, err := camTable(client)
		Expect(err).ShouldNot(HaveOccurred())
		if len(cam) > 0 {
			break
		}
		log.Info("waiting for client to connect")
		time.Sleep(time.Second)
	}
})

func camTable(client http.Client) (map[string]int, error) {
	res, err := client.Get("http://unix/cam")
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	var cam map[string]int
	if err := json.NewDecoder(res.Body).Decode(&cam); err != nil {
		return nil, err
	}
	return cam, nil
}

var _ = AfterSuite(func() {
	if host != nil {
		if err := host.Process.Kill(); err != nil {
			log.Error(err)
		}
	}
	if client != nil {
		if err := client.Process.Kill(); err != nil {
			log.Error(err)
		}
	}
})
