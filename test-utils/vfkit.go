//go:build darwin

package e2eutils

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	vfkit "github.com/crc-org/vfkit/pkg/config"
	"golang.org/x/mod/semver"
)

type VfkitVMConfig struct {
	DiskImage    string
	EFIStore     string
	VfkitSock    string
	IgnFile      string
	IgnitionSock string
}

func VfkitCmd(cfg VfkitVMConfig) (*exec.Cmd, error) {
	bootloader := vfkit.NewEFIBootloader(cfg.EFIStore, true)
	vm := vfkit.NewVirtualMachine(2, 2048, bootloader)
	disk, err := vfkit.VirtioBlkNew(cfg.DiskImage)
	if err != nil {
		return nil, err
	}
	if err = vm.AddDevice(disk); err != nil {
		return nil, err
	}
	net, err := vfkit.VirtioNetNew("5a:94:ef:e4:0c:ee")
	if err != nil {
		return nil, err
	}
	net.SetUnixSocketPath(cfg.VfkitSock)
	if err = vm.AddDevice(net); err != nil {
		return nil, err
	}
	ignition, err := vfkit.IgnitionNew(cfg.IgnFile, cfg.IgnitionSock)
	if err != nil {
		return nil, err
	}
	vm.Ignition = ignition
	return vm.Cmd(VfkitExecutable())
}

func VfkitVersion() (float64, error) {
	executable := VfkitExecutable()
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

func VfkitExecutable() string {
	path, err := exec.LookPath("vfkit")
	if err == nil && path != "" {
		return path
	}
	return ""
}
