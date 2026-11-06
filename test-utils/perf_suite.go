package e2eutils

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	gvproxyclient "github.com/containers/gvisor-tap-vsock/pkg/client"
	"github.com/containers/gvisor-tap-vsock/pkg/types"
	e2e "github.com/containers/gvisor-tap-vsock/test"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

type SuiteConfig struct {
	Sock         string
	SSHPort      int
	IgnitionUser string
	PasswordHash string
	KeyPrefix    string
	IgnPrefix    string
	ArtifactType string
	FormatType   string

	DeployTestCompanion bool

	ConfigureGvproxy    func(cmd *types.GvproxyCommand)
	ModifyGvproxyCmd    func(cmd *exec.Cmd) *exec.Cmd
	SetupVM             func(imagePath, ignFile string) (*exec.Cmd, error)
	PreSetup            func()
	PostTeardown        func()
	ExtraGvproxySockets []string
}

type SuiteHelper struct {
	Cfg            SuiteConfig
	TmpDir         string
	BinDir         string
	Host           *exec.Cmd
	Client         *exec.Cmd
	PrivateKeyFile string
	PublicKeyFile  string
	IgnFile        string
}

func NewSuiteHelper(cfg SuiteConfig) *SuiteHelper {
	return &SuiteHelper{Cfg: cfg}
}

func (h *SuiteHelper) InitFlags() {
	flag.StringVar(&h.TmpDir, "tmpDir", "../tmp", "temporary working directory")
	flag.StringVar(&h.BinDir, "bin", "../bin", "directory with compiled binaries")
}

func (h *SuiteHelper) deriveFilePaths() {
	h.PrivateKeyFile = filepath.Join(h.TmpDir, h.Cfg.KeyPrefix)
	h.PublicKeyFile = h.PrivateKeyFile + ".pub"
	h.IgnFile = filepath.Join(h.TmpDir, h.Cfg.IgnPrefix+".ign")
}

func (h *SuiteHelper) gvproxyCmd() *exec.Cmd {
	cmd := types.NewGvproxyCommand()
	cmd.AddEndpoint(fmt.Sprintf("unix://%s", h.Cfg.Sock))
	cmd.SSHPort = h.Cfg.SSHPort
	h.Cfg.ConfigureGvproxy(&cmd)
	return cmd.Cmd(filepath.Join(h.BinDir, "gvproxy"))
}

func (h *SuiteHelper) SetupSuite() {
	h.deriveFilePaths()

	if h.Cfg.PreSetup != nil {
		h.Cfg.PreSetup()
	}

	gomega.Expect(os.MkdirAll(filepath.Join(h.TmpDir, "disks"), os.ModePerm)).Should(gomega.Succeed())

	downloader, err := NewFcosDownloader(filepath.Join(h.TmpDir, "disks"))
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
	image, err := downloader.DownloadImage(h.Cfg.ArtifactType, h.Cfg.FormatType)
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

	publicKey, err := CreateSSHKeys(h.PublicKeyFile, h.PrivateKeyFile)
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

	err = CreateIgnition(h.IgnFile, publicKey, h.Cfg.IgnitionUser, h.Cfg.PasswordHash)
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

	_ = os.Remove(h.Cfg.Sock)

	h.Host = h.gvproxyCmd()
	if h.Cfg.ModifyGvproxyCmd != nil {
		h.Host = h.Cfg.ModifyGvproxyCmd(h.Host)
	}
	h.Host.Stderr = os.Stderr
	h.Host.Stdout = os.Stdout
	gomega.Expect(h.Host.Start()).Should(gomega.Succeed())

	waitSockets := append([]string{h.Cfg.Sock}, h.Cfg.ExtraGvproxySockets...)
	err = WaitGvproxy(h.Host, waitSockets...)
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

	h.Client, err = h.Cfg.SetupVM(image, h.IgnFile)
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
	h.Client.Stderr = os.Stderr
	h.Client.Stdout = os.Stdout
	gomega.Expect(h.Client.Start()).Should(gomega.Succeed())
	err = WaitSSH(h.Client, h.SSHExec)
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

	if h.Cfg.DeployTestCompanion {
		err = h.SCP(filepath.Join(h.BinDir, "test-companion"), "/tmp/test-companion")
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

		cmd := h.SSHCommand("sudo /tmp/test-companion")
		gomega.Expect(cmd.Start()).ShouldNot(gomega.HaveOccurred())
		time.Sleep(5 * time.Second)
	}
}

func (h *SuiteHelper) TeardownSuite() {
	if h.Host != nil {
		if err := h.Host.Process.Kill(); err != nil {
			log.Error(err)
		}
	}
	if h.Client != nil {
		if err := h.Client.Process.Kill(); err != nil {
			log.Error(err)
		}
	}
	if h.Cfg.PostTeardown != nil {
		h.Cfg.PostTeardown()
	}
}

func (h *SuiteHelper) SSHExec(cmd ...string) ([]byte, error) {
	return h.SSHCommand(cmd...).Output()
}

func (h *SuiteHelper) SSHCommand(cmd ...string) *exec.Cmd {
	return exec.Command("ssh",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=no",
		"-o", "IdentitiesOnly=yes",
		"-i", h.PrivateKeyFile,
		"-p", strconv.Itoa(h.Cfg.SSHPort),
		fmt.Sprintf("%s@127.0.0.1", h.Cfg.IgnitionUser), "--", strings.Join(cmd, " ")) // #nosec G204
}

func (h *SuiteHelper) SCP(src, dst string) error {
	sshCmd := exec.Command("scp",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=no",
		"-o", "IdentitiesOnly=yes",
		"-i", h.PrivateKeyFile,
		"-P", strconv.Itoa(h.Cfg.SSHPort),
		src,
		fmt.Sprintf("%s@127.0.0.1:%s", h.Cfg.IgnitionUser, dst)) // #nosec G204
	sshCmd.Stderr = os.Stderr
	sshCmd.Stdout = os.Stdout
	return sshCmd.Run()
}

func (h *SuiteHelper) SCPFromVM(src, dst string) error {
	sshCmd := exec.Command("scp",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=no",
		"-o", "IdentitiesOnly=yes",
		"-i", h.PrivateKeyFile,
		"-P", strconv.Itoa(h.Cfg.SSHPort),
		fmt.Sprintf("%s@127.0.0.1:%s", h.Cfg.IgnitionUser, src),
		dst) // #nosec G204
	sshCmd.Stderr = os.Stderr
	sshCmd.Stdout = os.Stdout
	return sshCmd.Run()
}

func (h *SuiteHelper) NewGvproxyAPIClient() *gvproxyclient.Client {
	return gvproxyclient.New(&http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", h.Cfg.Sock)
			},
		},
	}, "http://base")
}

func (h *SuiteHelper) ReportAfterSuite() bool {
	ginkgo.ReportAfterSuite("performance summary", func(report ginkgo.Report) {
		e2e.PrintPerformanceSummary(report)
	})
	return true
}
