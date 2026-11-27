package e2e_performance_qemu

import (
	"net"
	"os/exec"
	"strconv"
	"testing"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
	e2e_utils "github.com/containers/gvisor-tap-vsock/test-utils"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestSuite(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "gvisor-tap-vsock performance suite (qemu)")
}

const (
	sock     = "/tmp/gvproxy-api-perf-qemu.sock"
	qemuPort = 5556
	sshPort  = 2225
	qconLog  = "qcon-perf.log"

	ignitionUser = "test"
	// #nosec "test" (for manual usage)
	ignitionPasswordHash = "$y$j9T$TqJWt3/mKJbH0sYi6B/LD1$QjVRuUgntjTHjAdAkqhkr4F73m.Be4jBXdAaKw98sPC" // notsecret
)

var helper = e2e_utils.NewSuiteHelper(e2e_utils.SuiteConfig{
	Sock:                sock,
	SSHPort:             sshPort,
	IgnitionUser:        ignitionUser,
	PasswordHash:        ignitionPasswordHash,
	KeyPrefix:           "id_test_perf_qemu",
	IgnPrefix:           "test-perf-qemu",
	ArtifactType:        "qemu",
	FormatType:          "qcow2.xz",
	DeployTestCompanion: true,
	ConfigureGvproxy: func(cmd *types.GvproxyCommand) {
		cmd.AddQemuSocket("tcp://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(qemuPort)))
	},
	SetupVM: func(imagePath, ignFile string) (*exec.Cmd, error) {
		qemuC := newQemuCmd()
		qemuC.SetIgnition(ignFile)
		qemuC.SetDrive(imagePath, true)
		qemuC.SetNetdevSocket(net.JoinHostPort("127.0.0.1", strconv.Itoa(qemuPort)), "5a:94:ef:e4:0c:ee")
		qemuC.SetSerial(qconLog)
		return qemuC.Cmd(qemuExecutable())
	},
})

func init() {
	helper.InitFlags()
}

var _ = ginkgo.BeforeSuite(func() {
	helper.SetupSuite()
})

var _ = ginkgo.AfterSuite(func() {
	helper.TeardownSuite()
})

var _ = helper.ReportAfterSuite()
