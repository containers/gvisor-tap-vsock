package e2e

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

func TestSuite(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "gvisor-tap-vsock suite")
}

const (
	sock             = "/tmp/gvproxy-api.sock"
	qemuPort         = 5555
	sshPort          = 2222
	ignitionUser     = "test"
	ignitionPassword = "test"
)

var (
	tmpDir string
	binDir string
	host   *exec.Cmd
	client *exec.Cmd
)

func init() {
	flag.StringVar(&tmpDir, "tmpDir", "../tmp", "temporary working directory")
	flag.StringVar(&binDir, "bin", "../bin", "directory with compiled binaries")
}

var _ = BeforeSuite(func() {
	Expect(os.MkdirAll(filepath.Join(tmpDir, "disks"), os.ModePerm)).Should(Succeed())

	downloader, err := NewFcosDownloader(filepath.Join(tmpDir, "disks"))
	Expect(err).ShouldNot(HaveOccurred())
	qemuImage, err := downloader.DownloadImage()
	Expect(err).ShouldNot(HaveOccurred())

	_ = os.Remove(sock)
	// #nosec
	host = exec.Command(filepath.Join(binDir, "gvproxy"), fmt.Sprintf("--listen=unix://%s", sock), fmt.Sprintf("--listen-qemu=tcp://127.0.0.1:%d", qemuPort))
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

	template := `%s -m 2048 -nographic -snapshot -drive if=virtio,file=%s -fw_cfg name=opt/com.coreos/config,file=%s -netdev socket,id=vlan,connect=127.0.0.1:%d -device virtio-net-pci,netdev=vlan,mac=5a:94:ef:e4:0c:ee`
	// #nosec
	client = exec.Command(qemuExecutable(), strings.Split(fmt.Sprintf(template, qemuArgs(), qemuImage, filepath.Join("testdata", "test.ign"), qemuPort), " ")...)
	Expect(client.Start()).Should(Succeed())
	go func() {
		if err := client.Wait(); err != nil {
			log.Error(err)
		}
	}()

	for {
		_, err := sshExec("whoami")
		if err == nil {
			break
		}
		log.Infof("waiting for client to connect: %v", err)
		time.Sleep(time.Second)
	}
})

func qemuExecutable() string {
	if runtime.GOOS == "darwin" {
		return "qemu-system-x86_64"
	}
	return "qemu-kvm"
}

func qemuArgs() string {
	if runtime.GOOS == "darwin" {
		return "-machine q35,accel=hvf:tcg -smp 4"
	}
	return "-cpu host"
}

func sshExec(cmd ...string) ([]byte, error) {
	client, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", sshPort), &ssh.ClientConfig{
		User: ignitionUser,
		Auth: []ssh.AuthMethod{
			ssh.Password(ignitionPassword),
		},
		// #nosec
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()

	return sess.CombinedOutput(strings.Join(cmd, " "))
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
