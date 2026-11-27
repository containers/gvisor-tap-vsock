package e2e_performance_qemu

import (
	"fmt"
	"os/exec"
	"runtime"
	"strconv"

	e2e_utils "github.com/containers/gvisor-tap-vsock/test-utils"
)

type qemuCmd struct {
	memoryMiB         int
	vcpus             int
	model             string
	drivePath         string
	driveSnapshot     bool
	netdevConnectPath string
	netdevMac         string
	serialPath        string
	ignFile           string
}

const (
	defaultMemory   = 2048
	defaultVcpus    = 4
	defaultCpuModel = "host"
)

func newQemuCmd() *qemuCmd {
	return &qemuCmd{}
}

func (cmd *qemuCmd) SetDrive(path string, snapshot bool) {
	cmd.drivePath = path
	cmd.driveSnapshot = snapshot
}

func (cmd *qemuCmd) SetNetdevSocket(address string, mac string) {
	cmd.netdevConnectPath = address
	cmd.netdevMac = mac
}

func (cmd *qemuCmd) SetSerial(path string) {
	cmd.serialPath = path
}

func (cmd *qemuCmd) SetIgnition(ignFile string) {
	cmd.ignFile = ignFile
}

func (cmd *qemuCmd) Cmd(qemuPath string) (*exec.Cmd, error) {
	efiArgs, err := efiArgs()
	if err != nil {
		return nil, err
	}

	args := cmd.machineArgs()
	args = append(args, efiArgs...)
	args = append(args, cmd.memoryArgs()...)
	args = append(args, cmd.vcpusArgs()...)
	args = append(args, "-nographic")
	args = append(args, cmd.driveArgs()...)
	args = append(args, cmd.serialArgs()...)
	args = append(args, cmd.ignitionArgs()...)
	args = append(args, cmd.netdevArgs()...)

	return exec.Command(qemuPath, args...), nil // #nosec G204
}

func (cmd *qemuCmd) memoryArgs() []string {
	mem := cmd.memoryMiB
	if mem == 0 {
		mem = defaultMemory
	}
	return []string{"-m", strconv.Itoa(mem)}
}

func (cmd *qemuCmd) vcpusArgs() []string {
	vcpus := cmd.vcpus
	if vcpus == 0 {
		vcpus = defaultVcpus
	}
	model := cmd.model
	if model == "" {
		model = defaultCpuModel
	}
	return []string{"-smp", strconv.Itoa(vcpus), "-cpu", model}
}

func (cmd *qemuCmd) driveArgs() []string {
	if cmd.drivePath == "" {
		return nil
	}
	if cmd.driveSnapshot {
		return []string{"-drive", fmt.Sprintf("if=virtio,file=%s,snapshot=on", cmd.drivePath)}
	}
	return []string{"-drive", fmt.Sprintf("if=virtio,file=%s", cmd.drivePath)}
}

func (cmd *qemuCmd) netdevArgs() []string {
	return []string{
		"-netdev", fmt.Sprintf("socket,id=vlan,connect=%s", cmd.netdevConnectPath),
		"-device", fmt.Sprintf("virtio-net-pci,netdev=vlan,mac=%s", cmd.netdevMac),
	}
}

func (cmd *qemuCmd) serialArgs() []string {
	if cmd.serialPath == "" {
		return nil
	}
	return []string{"-serial", fmt.Sprintf("file:%s", cmd.serialPath)}
}

func (cmd *qemuCmd) ignitionArgs() []string {
	if cmd.ignFile == "" {
		return nil
	}
	return []string{"-fw_cfg", fmt.Sprintf("name=opt/com.coreos/config,file=%s", cmd.ignFile)}
}

func (cmd *qemuCmd) machineArgs() []string {
	return []string{"-machine", fmt.Sprintf("%s,accel=%s:tcg", machine(), accel())}
}

func qemuExecutable() string {
	qemuBinaries := []string{"qemu-kvm", fmt.Sprintf("qemu-system-%s", e2e_utils.CoreosArch())}
	for _, binary := range qemuBinaries {
		path, err := exec.LookPath(binary)
		if err == nil && path != "" {
			return path
		}
	}
	return ""
}

func machine() string {
	switch runtime.GOARCH {
	case "amd64":
		return "q35"
	case "arm64":
		return "virt"
	default:
		panic(fmt.Sprintf("unsupported arch: %s", runtime.GOARCH))
	}
}

func accel() string {
	if runtime.GOOS == "darwin" {
		return "hvf"
	}
	return "kvm"
}
