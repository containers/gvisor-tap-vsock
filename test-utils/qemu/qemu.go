package qemu

import (
	"fmt"
	"os/exec"
	"runtime"
	"strconv"

	e2e_utils "github.com/containers/gvisor-tap-vsock/test-utils"
)

type Cmd struct {
	// memory
	memoryMiB int

	// vcpus
	vcpus int
	model string

	// disk image
	drivePath     string
	driveSnapshot bool // if true, changes to the disk image won’t be written to disk

	// networking
	netdevConnectPath string
	netdevMac         string

	// serial
	serialPath string

	// ignition
	ignFile string
}

const (
	defaultMemory   = 2048
	defaultVcpus    = 4
	defaultCpuModel = "host"
)

func NewCmd() *Cmd {
	return &Cmd{}
}

func (cmd *Cmd) SetMemory(memoryMiB int) {
	cmd.memoryMiB = memoryMiB
}

func (cmd *Cmd) memoryArgs() []string {
	mem := cmd.memoryMiB
	if mem == 0 {
		mem = defaultMemory
	}
	return []string{"-m", strconv.Itoa(mem)}
}

func (cmd *Cmd) SetVcpus(vcpus int, model string) {
	cmd.vcpus = vcpus
	cmd.model = model
}

func (cmd *Cmd) vcpusArgs() []string {
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

func (cmd *Cmd) SetDrive(path string, snapshot bool) {
	cmd.drivePath = path
	cmd.driveSnapshot = snapshot
}

func (cmd *Cmd) driveArgs() []string {
	if cmd.drivePath == "" {
		return nil
	}
	if cmd.driveSnapshot {
		return []string{"-drive", fmt.Sprintf("if=virtio,file=%s,snapshot=on", cmd.drivePath)}
	}
	return []string{"-drive", fmt.Sprintf("if=virtio,file=%s", cmd.drivePath)}
}

func (cmd *Cmd) SetNetdevSocket(address string, mac string) {
	cmd.netdevConnectPath = address
	cmd.netdevMac = mac
}

func (cmd *Cmd) netdevArgs() []string {
	return []string{
		"-netdev",
		fmt.Sprintf("socket,id=vlan,connect=%s", cmd.netdevConnectPath),
		"-device",
		fmt.Sprintf("virtio-net-pci,netdev=vlan,mac=%s", cmd.netdevMac),
	}
}

func (cmd *Cmd) SetSerial(path string) {
	cmd.serialPath = path
}

func (cmd *Cmd) serialArgs() []string {
	if cmd.serialPath == "" {
		return nil
	}
	return []string{"-serial", fmt.Sprintf("file:%s", cmd.serialPath)}
}

func (cmd *Cmd) SetIgnition(ignFile string) {
	cmd.ignFile = ignFile
}

func (cmd *Cmd) ignitionArgs() []string {
	if cmd.ignFile == "" {
		return nil
	}
	return []string{"-fw_cfg", fmt.Sprintf("name=opt/com.coreos/config,file=%s", cmd.ignFile)}
}

func (cmd *Cmd) machineArgs() []string {
	return []string{"-machine", fmt.Sprintf("%s,accel=%s:tcg", machine(), accel())}
}

func (cmd *Cmd) Cmd() (*exec.Cmd, error) {
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

	qemuPath := executable()
	return exec.Command(qemuPath, args...), nil
}

func executable() string {
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
