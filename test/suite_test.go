package e2e

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

func TestVpnkit2(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Vpnkit2 Suite")
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
	Expect(os.Remove(sock)).Should(Succeed())
	// #nosec
	host = exec.Command(filepath.Join(binDir, "host"), "-debug", fmt.Sprintf("--url=unix://%s", sock))
	host.Stderr = os.Stderr
	host.Stdout = os.Stdout
	Expect(host.Start()).Should(Succeed())

	// #nosec
	client = exec.Command("sudo", filepath.Join(binDir, "vm"), fmt.Sprintf("--url=unix://%s", sock), fmt.Sprintf("--change-default-route=%v", changeDefaultRoute))
	client.Stderr = os.Stderr
	client.Stdout = os.Stdout
	Expect(client.Start()).Should(Succeed())

	time.Sleep(2 * time.Second)
})

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
