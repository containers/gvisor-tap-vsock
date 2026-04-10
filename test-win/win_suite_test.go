//go:build windows

package e2ewin

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	e2e_utils "github.com/containers/gvisor-tap-vsock/test-utils"

	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
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

	ignitionIsoFile, err := CreateIgnition(publicKey, ignitionUser, ignitionPasswordHash, networkHVSock.Port, filepath.Join(binDir, "gvforwarder"), tmpDir)
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

	errors := make(chan error)

	//gvproxy.exe -listen vsock://0000E62B-FACB-11E6-BD58-64006A7986D3 -mtu 1500 -ssh-port 54758 -forward-sock npipe://./pipe/podman-machine-default  -forward-sock unix:///C:/Users/yevhen/AppData/Local/Temp/podman/podman-machine-default-api.sock -forward-dest /run/user/1000/podman/podman.sock -forward-dest /run/user/1000/podman/podman.sock -forward-user core -forward-user core  -forward-identity C:\\Users\\yevhen\\.local\\share\\containers\\podman\\machine\\machine -forward-identity C:\\Users\\yevhen\\.local\\share\\containers\\podman\\machine\\machine  -pid-file C:\\Users\\yevhen\\AppData\\Local\\Temp\\podman\\gvproxy.pid -log-file C:\\Users\\yevhen\\AppData\\Local\\Temp\\podman\\gvproxy.log
	//fmt.Sprintf("-forward-sock npipe:%s", pipeName)
	gvproxyArgs := []string{fmt.Sprintf("--ssh-port=%d", sshPort), fmt.Sprintf("--listen=vsock://%s", networkHVSock.KeyName)}
	if *debugEnabled {
		// TODO: implement debug support for Windows
		logrus.Warn("Debug mode not yet implemented for Windows tests")
	} else {
		// #nosec
		host = exec.Command(filepath.Join(binDir, "gvproxy.exe"), gvproxyArgs...)
	}

	host.Stderr = os.Stderr
	host.Stdout = os.Stdout
	gomega.Expect(host.Start()).Should(gomega.Succeed())
	go func() {
		if err := host.Wait(); err != nil {
			logrus.Error(err)
			errors <- err
		}
	}()

	time.Sleep(2 * time.Second)

	err = StartVM(vmName)
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
waitLoop:
	for {
		_, err := sshExec("whoami")
		if err == nil {
			// install bind-utils and net-tools to be able to use nslookup and ping
			sshExec("sudo dnf install -y bind-utils net-tools")
			break waitLoop
		}

		select {
		case err := <-errors:
			logrus.Errorf("Error %v", err)
			// this expect will always fail so the tests stop
			gomega.Expect(err).To(gomega.Equal(nil))
			break waitLoop
		case <-time.After(1 * time.Second):
			logrus.Infof("waiting for client to connect: %v", err)
		}
	}

	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
})

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
			logrus.Error(err)
		}
	}
	cleanup()
})
