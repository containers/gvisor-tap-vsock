package e2eqemu

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
	e2e_utils "github.com/containers/gvisor-tap-vsock/test-utils"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

func TestSuite(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "gvisor-tap-vsock suite")
}

const (
	sock           = "/tmp/gvproxy-api.sock"
	qemuPort       = 5555
	sshPort        = 2222
	ignitionUser   = "test"
	qconLog        = "qcon.log"
	podmanSock     = "/run/user/1001/podman/podman.sock"
	podmanRootSock = "/run/podman/podman.sock"

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
)

func init() {
	flag.StringVar(&tmpDir, "tmpDir", "../tmp", "temporary working directory")
	flag.StringVar(&binDir, "bin", "../bin", "directory with compiled binaries")
	privateKeyFile = filepath.Join(tmpDir, "id_test_qemu")
	publicKeyFile = privateKeyFile + ".pub"
	ignFile = filepath.Join(tmpDir, "test.ign")
	forwardSock = filepath.Join(tmpDir, "podman-remote.sock")
	forwardRootSock = filepath.Join(tmpDir, "podman-root-remote.sock")

}

func gvproxyCmd() *exec.Cmd {
	cmd := types.NewGvproxyCommand()
	cmd.AddEndpoint(fmt.Sprintf("unix://%s", sock))
	cmd.AddQemuSocket("tcp://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(qemuPort)))
	cmd.AddForwardSock(forwardSock)
	cmd.AddForwardDest(podmanSock)
	cmd.AddForwardUser(ignitionUser)
	cmd.AddForwardIdentity(privateKeyFile)

	cmd.AddForwardSock(forwardRootSock)
	cmd.AddForwardDest(podmanRootSock)
	cmd.AddForwardUser("root")
	cmd.AddForwardIdentity(privateKeyFile)

	return cmd.Cmd(filepath.Join(binDir, "gvproxy"))
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

	_ = os.Remove(sock)

	host = gvproxyCmd()
	host.Stderr = os.Stderr
	host.Stdout = os.Stdout
	gomega.Expect(host.Start()).Should(gomega.Succeed())
	err = e2e_utils.WaitGvproxy(host, sock)
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

	qemuCmd := newQemuCmd()
	qemuCmd.SetIgnition(ignFile)
	qemuCmd.SetDrive(qemuImage, true)
	qemuCmd.SetNetdevSocket(net.JoinHostPort("127.0.0.1", strconv.Itoa(qemuPort)), "5a:94:ef:e4:0c:ee")
	qemuCmd.SetSerial(qconLog)
	client, err = qemuCmd.Cmd(qemuExecutable())
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
	client.Stderr = os.Stderr
	client.Stdout = os.Stdout
	gomega.Expect(client.Start()).Should(gomega.Succeed())
	err = e2e_utils.WaitSSH(client, sshExec)
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

	err = scp(filepath.Join(binDir, "test-companion"), "/tmp/test-companion")
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

	// start an embedded DNS and http server in the VM. Wait a bit for the server to start.
	cmd := sshCommand("sudo /tmp/test-companion")
	gomega.Expect(cmd.Start()).ShouldNot(gomega.HaveOccurred())
	time.Sleep(5 * time.Second)
})

func scp(src, dst string) error {
	sshCmd := exec.Command("scp",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=no",
		"-o", "IdentitiesOnly=yes",
		"-i", privateKeyFile,
		"-P", strconv.Itoa(sshPort),
		src,
		fmt.Sprintf("%s@127.0.0.1:%s", ignitionUser, dst)) // #nosec G204
	sshCmd.Stderr = os.Stderr
	sshCmd.Stdout = os.Stdout
	return sshCmd.Run()
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
		"-p", strconv.Itoa(sshPort),
		fmt.Sprintf("%s@127.0.0.1", ignitionUser), "--", strings.Join(cmd, " ")) // #nosec G204
	return sshCmd
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
