//go:build darwin

package e2evfkit

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
	e2e_utils "github.com/containers/gvisor-tap-vsock/test-utils"
	vfkit "github.com/crc-org/vfkit/pkg/config"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"golang.org/x/mod/semver"
)

func TestSuite(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "gvisor-tap-vsock suite")
}

const (
	sock         = "/tmp/gvproxy-api-vfkit.sock"
	vfkitSock    = "/tmp/vfkit.sock"
	ignitionSock = "/tmp/ignition.sock"
	sshPort      = 2223
	ignitionUser = "test"
	// #nosec "test" (for manual usage)
	ignitionPasswordHash = "$y$j9T$TqJWt3/mKJbH0sYi6B/LD1$QjVRuUgntjTHjAdAkqhkr4F73m.Be4jBXdAaKw98sPC" // notsecret
	efiStore             = "efi-variable-store"
	vfkitVersionNeeded   = 0.6
)

var (
	tmpDir         string
	binDir         string
	host           *exec.Cmd
	client         *exec.Cmd
	privateKeyFile string
	publicKeyFile  string
	ignFile        string
	cmdDir         string
)

var debugEnabled = flag.Bool("debug", false, "enable debugger")

func init() {
	flag.StringVar(&tmpDir, "tmpDir", "../tmp", "temporary working directory")
	flag.StringVar(&binDir, "bin", "../bin", "directory with compiled binaries")
	privateKeyFile = filepath.Join(tmpDir, "id_test_vfkit")
	publicKeyFile = privateKeyFile + ".pub"
	ignFile = filepath.Join(tmpDir, "test.ign")
	cmdDir = "../cmd"
}

func gvproxyCmd() *exec.Cmd {
	cmd := types.NewGvproxyCommand()
	cmd.AddEndpoint(fmt.Sprintf("unix://%s", sock))
	cmd.AddVfkitSocket("unixgram://" + vfkitSock)
	cmd.SSHPort = sshPort

	return cmd.Cmd(filepath.Join(binDir, "gvproxy"))
}

func vfkitCmd(diskImage string) (*exec.Cmd, error) {
	bootloader := vfkit.NewEFIBootloader(efiStore, true)
	vm := vfkit.NewVirtualMachine(2, 2048, bootloader)
	disk, err := vfkit.VirtioBlkNew(diskImage)
	if err != nil {
		return nil, err
	}
	err = vm.AddDevice(disk)
	if err != nil {
		return nil, err
	}
	net, err := vfkit.VirtioNetNew("5a:94:ef:e4:0c:ee")
	if err != nil {
		return nil, err
	}
	net.SetUnixSocketPath(vfkitSock)
	err = vm.AddDevice(net)
	if err != nil {
		return nil, err
	}
	ignition, err := vfkit.IgnitionNew(ignFile, ignitionSock)
	if err != nil {
		return nil, err
	}
	vm.Ignition = ignition
	return vm.Cmd(vfkitExecutable())
}

var _ = ginkgo.BeforeSuite(func() {
	// clear the environment before running the tests. It may happen the tests were abruptly stopped earlier leaving a dirty env
	cleanup()

	// check if vfkit version is greater than v0.5 (ignition support is available starting from v0.6)
	version, err := vfkitVersion()
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
	gomega.Expect(version >= vfkitVersionNeeded).Should(gomega.BeTrue())

	// check if ssh port is free
	gomega.Expect(e2e_utils.IsPortAvailable(sshPort)).Should(gomega.BeTrue())

	gomega.Expect(os.MkdirAll(filepath.Join(tmpDir, "disks"), os.ModePerm)).Should(gomega.Succeed())

	downloader, err := e2e_utils.NewFcosDownloader(filepath.Join(tmpDir, "disks"))
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
	fcosImage, err := downloader.DownloadImage("applehv", "raw.gz")
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

	publicKey, err := e2e_utils.CreateSSHKeys(publicKeyFile, privateKeyFile)
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

	err = e2e_utils.CreateIgnition(ignFile, publicKey, ignitionUser, ignitionPasswordHash)
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

	errors := make(chan error)

outer:
	for panics := 0; ; panics++ {
		_ = os.Remove(sock)
		_ = os.Remove(vfkitSock)

		host = gvproxyCmd()
		if *debugEnabled {
			gvproxyArgs := host.Args[1:]
			dlvArgs := []string{"debug", "--headless", "--listen=:2345", "--api-version=2", "--accept-multiclient", filepath.Join(cmdDir, "gvproxy"), "--"}
			dlvArgs = append(dlvArgs, gvproxyArgs...)
			host = exec.Command("dlv", dlvArgs...)
		}

		host.Stderr = os.Stderr
		host.Stdout = os.Stdout
		gomega.Expect(host.Start()).Should(gomega.Succeed())
		go func() {
			if err := host.Wait(); err != nil {
				log.Error(err)
				errors <- err
			}
		}()

		for {
			_, err := os.Stat(sock)
			if os.IsNotExist(err) {
				log.Info("waiting for vfkit-api socket")
				time.Sleep(100 * time.Millisecond)
				continue
			}
			_, err = os.Stat(vfkitSock)
			if os.IsNotExist(err) {
				log.Info("waiting for vfkit socket")
				time.Sleep(100 * time.Millisecond)
				continue
			}
			break
		}

		client, err = vfkitCmd(fcosImage)
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		client.Stderr = os.Stderr
		client.Stdout = os.Stdout
		gomega.Expect(client.Start()).Should(gomega.Succeed())
		go func() {
			if err := client.Wait(); err != nil {
				log.Error(err)
				errors <- err
			}
		}()

		for {
			_, err := sshExec("whoami")
			if err == nil {
				break outer
			}

			select {
			case err := <-errors:
				log.Errorf("Error %v", err)
				// this expect will always fail so the tests stop
				gomega.Expect(err).To(gomega.Equal(nil))
				break outer
			case <-time.After(1 * time.Second):
				log.Infof("waiting for client to connect: %v", err)
			}
		}
	}

	time.Sleep(5 * time.Second)
})

func vfkitVersion() (float64, error) {
	executable := vfkitExecutable()
	if executable == "" {
		return 0, fmt.Errorf("vfkit executable not found")
	}
	out, err := exec.Command(executable, "-v").Output()
	if err != nil {
		return 0, err
	}
	version := strings.TrimPrefix(string(out), "vfkit version:")
	majorMinor := strings.TrimPrefix(semver.MajorMinor(strings.TrimSpace(version)), "v")
	versionF, err := strconv.ParseFloat(majorMinor, 64)
	if err != nil {
		return 0, err
	}
	return versionF, nil
}

func vfkitExecutable() string {
	vfkitBinaries := []string{"vfkit"}
	for _, binary := range vfkitBinaries {
		path, err := exec.LookPath(binary)
		if err == nil && path != "" {
			return path
		}
	}

	return ""
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

func cleanup() {
	_ = os.Remove(efiStore)
	_ = os.Remove(sock)
	_ = os.Remove(vfkitSock)

	// this should be handled by vfkit once https://github.com/crc-org/vfkit/pull/230 gets merged
	// it removes the ignition.sock file
	socketPath := filepath.Join(os.TempDir(), "ignition.sock")
	_ = os.Remove(socketPath)
}

func scp(src, dst string) error {
	sshCmd := exec.Command("/usr/bin/scp",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=no",
		"-o", "IdentitiesOnly=yes",
		"-i", privateKeyFile,
		"-P", strconv.Itoa(sshPort),
		src, dst) // #nosec G204
	sshCmd.Stderr = os.Stderr
	sshCmd.Stdout = os.Stdout
	return sshCmd.Run()
}
func scpToVM(src, dst string) error {
	return scp(src, fmt.Sprintf("%s@127.0.0.1:%s", ignitionUser, dst))
}

func scpFromVM(src, dst string) error {
	return scp(fmt.Sprintf("%s@127.0.0.1:%s", ignitionUser, src), dst)
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
	cleanup()
})
