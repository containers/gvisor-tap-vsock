package e2e

import (
	"fmt"
	"os"
	"path/filepath"
)

func efiArgs() (string, error) {
	// file may not exist, that's ok
	_ = os.Remove("ovmf_vars.fd")
	ovmfVars, err := os.Create("ovmf_vars.fd")
	if err != nil {
		return "", err
	}
	defer ovmfVars.Close()
	if err := ovmfVars.Truncate(67108864); err != nil {
		return "", err
	}

	edk2Path := getEdk2CodeFd("edk2-aarch64-code.fd")
	return fmt.Sprintf(`-drive file=%s,if=pflash,format=raw,readonly=on -drive file=%s,if=pflash,format=raw `, edk2Path, ovmfVars.Name()), nil
}

/*
 * When QEmu is installed in a non-default location in the system
 * we can use the qemu-system-* binary path to figure the install
 * location for Qemu and use it to look for edk2-code-fd
 */
func getEdk2CodeFdPathFromQemuBinaryPath() string {
	return filepath.Clean(filepath.Join(filepath.Dir(qemuExecutable()), "..", "share", "qemu"))
}

/*
 *  QEmu can be installed in multiple locations on MacOS, especially on
 *  Apple Silicon systems.  A build from source will likely install it in
 *  /usr/local/bin, whereas Homebrew package management standard is to
 *  install in /opt/homebrew
 */
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
