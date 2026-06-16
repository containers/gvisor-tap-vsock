package e2e_performance_qemu

import (
	"fmt"
	"os"
	"path/filepath"
)

func efiArgs() ([]string, error) {
	_ = os.Remove("ovmf_vars.fd")
	ovmfVars, err := os.Create("ovmf_vars.fd")
	if err != nil {
		return nil, err
	}
	defer ovmfVars.Close()
	if err := ovmfVars.Truncate(67108864); err != nil {
		return nil, err
	}

	edk2Path := getEdk2CodeFd("edk2-aarch64-code.fd")
	return []string{
		"-drive", fmt.Sprintf("file=%s,if=pflash,format=raw,readonly=on", edk2Path),
		"-drive", fmt.Sprintf("file=%s,if=pflash,format=raw", ovmfVars.Name()),
	}, nil
}

func getEdk2CodeFdPathFromQemuBinaryPath() string {
	return filepath.Clean(filepath.Join(filepath.Dir(qemuExecutable()), "..", "share", "qemu"))
}

func getEdk2CodeFd(name string) string {
	dirs := []string{
		getEdk2CodeFdPathFromQemuBinaryPath(),
		"/opt/homebrew/opt/podman/libexec/share/qemu",
		"/usr/local/share/qemu",
		"/opt/homebrew/share/qemu",
	}
	for _, dir := range dirs {
		fullpath := filepath.Join(dir, name)
		if _, err := os.Stat(fullpath); err == nil {
			return fullpath
		}
	}
	return name
}
