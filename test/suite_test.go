package e2e

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

func TestSuite(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "gvisor-tap-vsock suite")
}

const (
	sock         = "/tmp/gvproxy-api.sock"
	qemuPort     = 5555
	sshPort      = 2222
	ignitionUser = "test"
	qconLog      = "qcon.log"
	podmanSock   = "/run/user/1001/podman/podman.sock"

	// #nosec "test" (for manual usage)
	ignitionPasswordHash = "$y$j9T$TqJWt3/mKJbH0sYi6B/LD1$QjVRuUgntjTHjAdAkqhkr4F73m.Be4jBXdAaKw98sPC"
)

var (
	tmpDir         string
	binDir         string
	host           *exec.Cmd
	client         *exec.Cmd
	privateKeyFile string
	publicKeyFile  string
	ignFile        string
	forwardSock    string
)

func init() {
	flag.StringVar(&tmpDir, "tmpDir", "../tmp", "temporary working directory")
	flag.StringVar(&binDir, "bin", "../bin", "directory with compiled binaries")
	privateKeyFile = filepath.Join(tmpDir, "id_test")
	publicKeyFile = privateKeyFile + ".pub"
	ignFile = filepath.Join(tmpDir, "test.ign")
	forwardSock = filepath.Join(tmpDir, "podman-remote.sock")
}

var _ = BeforeSuite(func() {
	Expect(os.MkdirAll(filepath.Join(tmpDir, "disks"), os.ModePerm)).Should(Succeed())

	downloader, err := NewFcosDownloader(filepath.Join(tmpDir, "disks"))
	Expect(err).ShouldNot(HaveOccurred())
	qemuImage, err := downloader.DownloadImage()
	Expect(err).ShouldNot(HaveOccurred())

	publicKey, err := createSSHKeys()
	Expect(err).ShouldNot(HaveOccurred())

	err = CreateIgnition(ignFile, publicKey, ignitionUser, ignitionPasswordHash)
	Expect(err).ShouldNot(HaveOccurred())

outer:
	for panics := 0; ; panics++ {
		_ = os.Remove(sock)

		// #nosec
		host = exec.Command(filepath.Join(binDir, "gvproxy"), fmt.Sprintf("--listen=unix://%s", sock), fmt.Sprintf("--listen-qemu=tcp://127.0.0.1:%d", qemuPort),
			fmt.Sprintf("--forward-sock=%s", forwardSock), fmt.Sprintf("--forward-dest=%s", podmanSock), fmt.Sprintf("--forward-user=%s", ignitionUser),
			fmt.Sprintf("--forward-identity=%s", privateKeyFile))
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

		template := `%s -m 2048 -nographic -serial file:%s -snapshot -drive if=virtio,file=%s -fw_cfg name=opt/com.coreos/config,file=%s -netdev socket,id=vlan,connect=127.0.0.1:%d -device virtio-net-pci,netdev=vlan,mac=5a:94:ef:e4:0c:ee`
		// #nosec
		client = exec.Command(qemuExecutable(), strings.Split(fmt.Sprintf(template, qemuArgs(), qconLog, qemuImage, ignFile, qemuPort), " ")...)
		Expect(client.Start()).Should(Succeed())
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
			panic, err := panicCheck(qconLog)
			Expect(err).ShouldNot(HaveOccurred())

			if panic {
				Expect(panics).ToNot(BeNumerically(">", 15), "No more than 15 panics allowed")
				log.Info("Detected Kernel panic, retrying...")
				_ = client.Process.Kill()
				_ = host.Process.Kill()
				_ = os.Remove(qconLog)
				continue outer
			}

			log.Infof("waiting for client to connect: %v", err)
			time.Sleep(time.Second)
		}
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

func createSSHKeys() (string, error) {
	_ = os.Remove(publicKeyFile)
	_ = os.Remove(privateKeyFile)
	err := exec.Command("ssh-keygen", "-N", "", "-t", "ed25519", "-f", privateKeyFile).Run()
	if err != nil {
		return "", errors.Wrap(err, "Could not generate ssh keys")
	}

	return readPublicKey()
}

func readPublicKey() (string, error) {
	publicKey, err := ioutil.ReadFile(publicKeyFile)
	if err != nil {
		return "", nil
	}

	return strings.TrimSpace(string(publicKey)), nil
}

func parsePrivateKey(path string) (ssh.Signer, error) {
	key, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, err
	}
	return signer, nil
}

func sshExec(cmd ...string) ([]byte, error) {
	key, err := parsePrivateKey(privateKeyFile)
	if err != nil {
		return nil, err
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", sshPort), &ssh.ClientConfig{
		User: ignitionUser,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(key),
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

func panicCheck(con string) (bool, error) {
	file, err := os.Open(con)
	if err != nil {
		return false, err
	}

	_, _ = file.Seek(-500, os.SEEK_END)
	// Ignore seek errors (not enough content yet)

	contents := make([]byte, 500)
	_, err = io.ReadAtLeast(file, contents, len(contents))
	if err != nil {
		return false, err
	}

	return strings.Contains(string(contents), "end Kernel panic"), nil
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
