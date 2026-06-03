//go:build windows

package e2ewin

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
	e2e_utils "github.com/containers/gvisor-tap-vsock/test-utils"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

func TestSuite(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "gvisor-tap-vsock Windows suite")
}

const (
	pipeName     = "\\.\\pipe\\gvproxy-api-win"
	sshPort      = 2224
	ignitionUser = "test"
	// #nosec "test" (for manual usage)
	ignitionPasswordHash = "$y$j9T$TqJWt3/mKJbH0sYi6B/LD1$QjVRuUgntjTHjAdAkqhkr4F73m.Be4jBXdAaKw98sPC" // notsecret
	vmName               = "gvisor-win-test"
)

var (
	tmpDir         string
	binDir         string
	host           *exec.Cmd
	privateKeyFile string
	publicKeyFile  string
	ignFile        string
	cmdDir         string
	vmDiskPath     string // used by cleanup to remove disk after VM removal
)

var debugEnabled = flag.Bool("debug", false, "enable debugger")

func init() {
	flag.StringVar(&tmpDir, "tmpDir", "../tmp", "temporary working directory")
	flag.StringVar(&binDir, "bin", "../bin", "directory with compiled binaries")
	privateKeyFile = filepath.Join(tmpDir, "id_test_win")
	publicKeyFile = privateKeyFile + ".pub"
	ignFile = filepath.Join(tmpDir, "test.ign")
	cmdDir = "../cmd"
}

var _ = ginkgo.BeforeSuite(func() {
	// clear the environment before running the tests. It may happen the tests were abruptly stopped earlier leaving a dirty env
	cleanup()

	// check if ssh port is free
	// TODO: implement IsPortAvailable for Windows

	gomega.Expect(os.MkdirAll(filepath.Join(tmpDir, "disks"), os.ModePerm)).Should(gomega.Succeed())
	downloader, err := e2e_utils.NewFcosDownloader(filepath.Join(tmpDir, "disks"))
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
	fcosImage, err := downloader.DownloadImageFromURL("https://download.fedoraproject.org/pub/fedora/linux/releases/43/Cloud/x86_64/images/Fedora-Cloud-Base-Azure-43-1.6.x86_64.vhdfixed.xz")
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
	if strings.HasSuffix(fcosImage, ".vhdfixed") {
		// Rename the fcosImage file to have '.vhd' extension
		newFcosImage := strings.TrimSuffix(fcosImage, ".vhdfixed") + ".vhd"
		err = os.Rename(fcosImage, newFcosImage)
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		fcosImage = newFcosImage
	}
	// Convert to absolute path if needed
	fcosImage, err = filepath.Abs(fcosImage)
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

	publicKey, err := e2e_utils.CreateSSHKeys(publicKeyFile, privateKeyFile)
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

	networkHVSock, err := LoadHVSockRegistryEntryByPurpose(Network)
	if err != nil {

		networkHVSock, err = NewHVSockRegistryEntry(Network)
		if err != nil {
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		}
	}

	ignitionIsoFile, err := CreateCloudInit(publicKey, ignitionUser, ignitionPasswordHash, networkHVSock.Port, filepath.Join(binDir, "gvforwarder"), tmpDir)
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

	// // Gen 2 VMs require .vhdx; convert .vhd to .vhdx if needed and use that path for CreateVM and cleanup.
	diskPathForVM := fcosImage
	if strings.ToLower(filepath.Ext(fcosImage)) == ".vhd" {
		diskPathForVM, err = VHDPathForGen2(fcosImage)
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
	}

	vmDiskPath = diskPathForVM
	err = CreateVM(vmName, diskPathForVM, ignitionIsoFile, 4096, 4)
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

	host = gvproxyCmd(networkHVSock.KeyName)
	if *debugEnabled {
		log.Warn("Debug mode not yet implemented for Windows tests")
	}

	host.Stderr = os.Stderr
	host.Stdout = os.Stdout
	gomega.Expect(host.Start()).Should(gomega.Succeed())

	err = StartVM(vmName)
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

	err = e2e_utils.WaitSSH(host, sshExec)
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

	_, _ = sshExec("sudo dnf install -y bind-utils net-tools")
})

func gvproxyCmd(vsockKeyName string) *exec.Cmd {
	cmd := types.NewGvproxyCommand()
	cmd.AddEndpoint(fmt.Sprintf("vsock://%s", vsockKeyName))
	cmd.SSHPort = sshPort

	return cmd.Cmd(filepath.Join(binDir, "gvproxy.exe"))
}

func sshExec(cmd ...string) ([]byte, error) {
	out, err := sshCommand(cmd...).Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && len(exitErr.Stderr) > 0 {
			return out, fmt.Errorf("%w\nStderr: %s", err, string(exitErr.Stderr))
		}
	}
	return out, err
}

func sshCommand(cmd ...string) *exec.Cmd {
	sshCmd := exec.Command("ssh",
		"-o", "UserKnownHostsFile="+os.DevNull,
		"-o", "StrictHostKeyChecking=no",
		"-o", "IdentitiesOnly=yes",
		"-i", privateKeyFile,
		"-p", strconv.Itoa(sshPort),
		fmt.Sprintf("%s@127.0.0.1", ignitionUser), "--", strings.Join(cmd, " ")) // #nosec G204
	return sshCmd
}

func cleanup() {
	_ = os.Remove(pipeName)
	_ = RemoveAllHVSockRegistryEntries()
	exists, _ := VMExists(vmName)
	if exists {
		_ = StopVM(vmName)
		_ = RemoveVM(vmName)
		if vmDiskPath != "" {
			_ = os.Remove(vmDiskPath)
		}
	}
}

var _ = ginkgo.AfterSuite(func() {
	if host != nil {
		if err := host.Process.Kill(); err != nil {
			log.Error(err)
		}
	}
	cleanup()
})
