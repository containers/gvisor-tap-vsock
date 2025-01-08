//go:build windows
// +build windows

package e2e_win_qemu

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	e2e_utils "github.com/containers/gvisor-tap-vsock/test-utils"
)

func TestSuite(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "win-sshproxy suite")
}

const (
	qemuPort            = 5554
	ignitionUser        = "test"
	podmanSock          = "/run/user/1001/podman/podman.sock"
	podmanRootSock      = "/run/podman/podman.sock"
	npipePodmanTestPath = "\\\\.\\pipe\\test-win-sshproxy"
	npipePodmanTest     = "npipe:////./pipe/test-win-sshproxy"

	// #nosec "test" (for manual usage)
	ignitionPasswordHash = "$y$j9T$TqJWt3/mKJbH0sYi6B/LD1$QjVRuUgntjTHjAdAkqhkr4F73m.Be4jBXdAaKw98sPC"
)

var (
	tmpDir          string
	binDir          string
	host            *exec.Cmd
	client          *exec.Cmd
	privateKeyFile  string
	publicKeyFile   string
	ignFile         string
	forwardSock     string
	forwardRootSock string
	qconLog         string
)

func init() {
	flag.StringVar(&tmpDir, "tmpDir", "..\\..\\tmp", "temporary working directory")
	flag.StringVar(&binDir, "bin", "..\\..\\bin", "directory with compiled binaries")
	privateKeyFile = filepath.Join(tmpDir, "id_test")
	publicKeyFile = privateKeyFile + ".pub"
	ignFile = filepath.Join(tmpDir, "test.ign")
	forwardSock = filepath.Join(tmpDir, "podman-remote.sock")
	forwardRootSock = filepath.Join(tmpDir, "podman-root-remote.sock")
	qconLog = filepath.Join(tmpDir, "qcon.log")
}

var _ = ginkgo.BeforeSuite(func() {
	gomega.Expect(os.MkdirAll(filepath.Join(tmpDir, "disks"), os.ModePerm)).Should(gomega.Succeed())

	downloader, err := e2e_utils.NewFcosDownloader(filepath.Join(tmpDir, "disks"))
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
	qemuImage, err := downloader.DownloadImage("qemu", "qcow2.xz")
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

	publicKey, err := e2e_utils.CreateSSHKeys(publicKeyFile, privateKeyFile)
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

	err = e2e_utils.CreateIgnition(ignFile, publicKey, ignitionUser, ignitionPasswordHash)
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

outer:
	for panics := 0; ; panics++ {
		template := `-m 2048 -nographic -serial file:%s -hda %s -fw_cfg name=opt/com.coreos/config,file=%s -nic user,hostfwd=tcp::%d-:22`

		// #nosec
		client = exec.Command(qemuExecutable(), strings.Split(fmt.Sprintf(template, qconLog, qemuImage, ignFile, qemuPort), " ")...)
		client.Stderr = os.Stderr
		client.Stdout = os.Stdout
		gomega.Expect(client.Start()).Should(gomega.Succeed())
		go func() {
			if err := client.Wait(); err != nil {
				log.Error(err)
			}
		}()

		for {
			_, err := sshExec("whoami")
			if err == nil {
				break outer
			}

			// Check for panic
			didPanic, err := panicCheck(qconLog)
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

			if didPanic {
				gomega.Expect(panics).ToNot(gomega.BeNumerically(">", 15), "No more than 15 panics allowed")
				log.Info("Detected Kernel panic, retrying...")
				_ = client.Process.Kill()
				_ = os.Remove(qconLog)
				continue outer
			}

			log.Infof("waiting for client to connect: %v", err)
			time.Sleep(time.Second)
		}
	}

	// #nosec
	host = exec.Command(filepath.Join(binDir, "win-sshproxy.exe"), "test", tmpDir, npipePodmanTest,
		fmt.Sprintf("ssh://%s@localhost:%d%s", ignitionUser, qemuPort, podmanSock), privateKeyFile)

	host.Stderr = os.Stderr
	host.Stdout = os.Stdout
	gomega.Expect(host.Start()).Should(gomega.Succeed())
	go func() {
		if err := host.Wait(); err != nil {
			log.Error(err)
		}
	}()

	time.Sleep(5 * time.Second)
})

func qemuExecutable() string {
	binary := fmt.Sprintf("qemu-system-%s.exe", e2e_utils.CoreosArch())
	path, err := exec.LookPath(binary)
	if err != nil {
		return ""
	}
	return path
}

func sshExec(cmd ...string) ([]byte, error) {
	return sshCommand(cmd...).Output()
}

func sshCommand(cmd ...string) *exec.Cmd {
	sshCmd := exec.Command("ssh",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=no",
		"-o", "IdentitiesOnly=yes",
		"-i", privateKeyFile,
		"-p", strconv.Itoa(qemuPort),
		fmt.Sprintf("%s@127.0.0.1", ignitionUser), "--", strings.Join(cmd, " ")) // #nosec G204
	return sshCmd
}

func panicCheck(con string) (bool, error) {
	file, err := os.Open(con)
	if err != nil {
		return false, err
	}

	_, _ = file.Seek(-500, io.SeekEnd)
	// Ignore seek errors (not enough content yet)

	contents := make([]byte, 500)
	_, err = io.ReadAtLeast(file, contents, len(contents))
	if err != nil && err != io.ErrUnexpectedEOF {
		return false, err
	}

	return strings.Contains(string(contents), "end Kernel panic"), nil
}

var _ = ginkgo.AfterSuite(func() {
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
