//go:build darwin

package e2evfkit

import (
	"flag"
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
	ginkgo.RunSpecs(t, "gvisor-tap-vsock suite")
}

const (
	sock               = "/tmp/gvproxy-api-vfkit.sock"
	servicesSock       = "/tmp/gvproxy-vfkit-services.sock"
	vfkitSock          = "/tmp/vfkit.sock"
	ignitionSock       = "/tmp/ignition.sock"
	sshPort            = 2223
	efiStore           = "efi-variable-store"
	vfkitVersionNeeded = 0.6

	ignitionUser = "test"
	// #nosec "test" (for manual usage)
	ignitionPasswordHash = "$y$j9T$TqJWt3/mKJbH0sYi6B/LD1$QjVRuUgntjTHjAdAkqhkr4F73m.Be4jBXdAaKw98sPC" // notsecret
)

var (
	debugEnabled = flag.Bool("debug", false, "enable debugger")
	cmdDir       = "../cmd"
)

var helper = e2e_utils.NewSuiteHelper(e2e_utils.SuiteConfig{
	Sock:         sock,
	SSHPort:      sshPort,
	IgnitionUser: ignitionUser,
	PasswordHash: ignitionPasswordHash,
	KeyPrefix:    "id_test_vfkit",
	IgnPrefix:    "test",
	ArtifactType: "applehv",
	FormatType:   "raw.gz",
	ConfigureGvproxy: func(cmd *types.GvproxyCommand) {
		cmd.AddVfkitSocket("unixgram://" + vfkitSock)
		cmd.AddServiceEndpoint("unix://" + servicesSock)
	},
	ModifyGvproxyCmd: func(cmd *exec.Cmd) *exec.Cmd {
		if !*debugEnabled {
			return cmd
		}
		gvproxyArgs := cmd.Args[1:]
		dlvArgs := []string{"debug", "--headless", "--listen=:2345", "--api-version=2", "--accept-multiclient", filepath.Join(cmdDir, "gvproxy"), "--"}
		dlvArgs = append(dlvArgs, gvproxyArgs...)
		return exec.Command("dlv", dlvArgs...) // #nosec G204
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
	ExtraGvproxySockets: []string{vfkitSock, servicesSock},
})

func init() {
	helper.InitFlags()
}

func scpToVM(src, dst string) error {
	return helper.SCP(src, dst)
}

func scpFromVM(src, dst string) error {
	return helper.SCPFromVM(src, dst)
}

func cleanup() {
	_ = os.Remove(efiStore)
	_ = os.Remove(sock)
	_ = os.Remove(servicesSock)
	_ = os.Remove(vfkitSock)
	socketPath := filepath.Join(os.TempDir(), "ignition.sock")
	_ = os.Remove(socketPath)
}

var _ = ginkgo.BeforeSuite(func() {
	helper.SetupSuite()
})

var _ = ginkgo.AfterSuite(func() {
	helper.TeardownSuite()
})
