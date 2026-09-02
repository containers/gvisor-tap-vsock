//go:build darwin

package e2e_performance_vfkit

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
	e2e_utils "github.com/containers/gvisor-tap-vsock/test-utils"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestSuite(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "gvisor-tap-vsock performance suite (vfkit)")
}

const (
	sock               = "/tmp/gvproxy-api-perf-vfkit.sock"
	vfkitSock          = "/tmp/vfkit-perf.sock"
	ignitionSock       = "/tmp/ignition-perf-vfkit.sock"
	sshPort            = 2224
	efiStore           = "efi-variable-store"
	vfkitVersionNeeded = 0.6

	ignitionUser = "test"
	// #nosec "test" (for manual usage)
	ignitionPasswordHash = "$y$j9T$TqJWt3/mKJbH0sYi6B/LD1$QjVRuUgntjTHjAdAkqhkr4F73m.Be4jBXdAaKw98sPC" // notsecret
)

var helper = e2e_utils.NewSuiteHelper(e2e_utils.SuiteConfig{
	Sock:                sock,
	SSHPort:             sshPort,
	IgnitionUser:        ignitionUser,
	PasswordHash:        ignitionPasswordHash,
	KeyPrefix:           "id_test_perf_vfkit",
	IgnPrefix:           "test-perf-vfkit",
	ArtifactType:        "applehv",
	FormatType:          "raw.gz",
	DeployTestCompanion: true,
	ConfigureGvproxy: func(cmd *types.GvproxyCommand) {
		cmd.AddVfkitSocket("unixgram://" + vfkitSock)
	},
	SetupVM: func(imagePath, ignFile string) (*exec.Cmd, error) {
		return e2e_utils.VfkitCmd(e2e_utils.VfkitVMConfig{
			DiskImage:    imagePath,
			EFIStore:     efiStore,
			VfkitSock:    vfkitSock,
			IgnFile:      ignFile,
			IgnitionSock: ignitionSock,
		})
	},
	PreSetup: func() {
		cleanup()

		version, err := e2e_utils.VfkitVersion()
		gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
		gomega.Expect(version >= vfkitVersionNeeded).Should(gomega.BeTrue())

		gomega.Expect(e2e_utils.IsPortAvailable(sshPort)).Should(gomega.BeTrue())
	},
	PostTeardown:        cleanup,
	ExtraGvproxySockets: []string{vfkitSock},
})

func init() {
	helper.InitFlags()
}

func cleanup() {
	_ = os.Remove(efiStore)
	_ = os.Remove(sock)
	_ = os.Remove(vfkitSock)
	socketPath := filepath.Join(os.TempDir(), "ignition-perf-vfkit.sock")
	_ = os.Remove(socketPath)
}

var _ = ginkgo.BeforeSuite(func() {
	helper.SetupSuite()
})

var _ = ginkgo.AfterSuite(func() {
	helper.TeardownSuite()
})

var _ = helper.ReportAfterSuite()
