//go:build windows

package e2ewin

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
)

// psExitHyperVAccessDenied is returned by checkHyperVAccessScript when Get-VM fails
// with access denied (detected via types/HRESULT/FQEID, not localized error text).
const psExitHyperVAccessDenied = 2

// checkHyperVAccessScript probes Hyper-V; exits 0 on success, 2 on access denied, 1 on other errors.
const checkHyperVAccessScript = `
$ErrorActionPreference = 'Stop'
try {
	Get-VM -ErrorAction Stop | Out-Null
	exit 0
} catch {
	$tid = $_.FullyQualifiedErrorId
	if ($tid -like '*UnauthorizedAccess*' -or $tid -like '*AccessDenied*') { exit 2 }
	$ex = $_.Exception
	while ($null -ne $ex) {
		if ($ex -is [System.UnauthorizedAccessException]) { exit 2 }
		if ($ex -is [System.ComponentModel.Win32Exception] -and $ex.NativeErrorCode -eq 5) { exit 2 }
		if ($ex.HResult -eq -2147024891) { exit 2 }
		$ex = $ex.InnerException
	}
	exit 1
}
`

// runPowerShell executes a PowerShell script and returns combined output and error.
func runPowerShell(script string) ([]byte, error) {
	// -NoProfile -NonInteractive -ExecutionPolicy Bypass for CI/unattended use
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	return cmd.CombinedOutput()
}

// checkHyperVAccess verifies the current user can interact with Hyper-V. If not, prints
// instructions to add the user to the Hyper-V Administrators group and returns an error.
func checkHyperVAccess() error {
	out, err := runPowerShell(checkHyperVAccessScript)
	if err == nil {
		return nil
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != psExitHyperVAccessDenied {
		return nil // Hyper-V missing, other cmdlet errors, etc.
	}
	msg := string(out)
	user := os.Getenv("USERNAME")
	if user == "" {
		user = os.Getenv("USER")
	}
	if user == "" {
		user = "<YourUsername>"
	}
	fmt.Fprintf(os.Stderr, `
The current user does not have rights to manage Hyper-V.
To run tests without Administrator privileges, add yourself to the Hyper-V Administrators group:

  Option 1 - Run in an elevated (Administrator) PowerShell or Command Prompt:
    net localgroup "Hyper-V Administrators" %s /add

  Option 2 - Via GUI: Computer Management → Local Users and Groups → Groups
    → "Hyper-V Administrators" → Add your user account.

Then log off and log back in (or restart) for the change to take effect.
`, user)
	return fmt.Errorf("Hyper-V access denied: %w: %s", err, msg)
}

// VMExists returns true if a Hyper-V VM with the given name exists.
// It first checks that the current user has rights to interact with Hyper-V; if not,
// it prints instructions and returns an error.
func VMExists(name string) (bool, error) {
	if err := checkHyperVAccess(); err != nil {
		return false, err
	}
	out, err := runPowerShell(fmt.Sprintf(`if (Get-VM -Name %q -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }`, name))
	if err != nil {
		if len(out) > 0 && strings.Contains(string(out), "Get-VM") {
			return false, fmt.Errorf("VMExists: %w: %s", err, string(out))
		}
		return false, nil
	}
	return true, nil
}

// VHDPathForGen2 returns the disk path to use for a Generation 2 VM. Generation 2 only supports
// .vhdx format; if vhdPath has a .vhd extension it is converted to .vhdx (same directory, same
// base name) and the new path is returned. Caller should use the returned path for CreateVM and
// for cleanup (e.g. vmDiskPath) so the converted file is removed after tests.
func VHDPathForGen2(vhdPath string) (string, error) {
	ext := strings.ToLower(filepath.Ext(vhdPath))
	if ext != ".vhd" {
		return vhdPath, nil
	}
	vhdxPath := vhdPath[:len(vhdPath)-len(ext)] + ".vhdx"
	script := fmt.Sprintf(`Convert-VHD -Path %q -DestinationPath %q`, vhdPath, vhdxPath)
	out, err := runPowerShell(script)
	if err != nil {
		return "", fmt.Errorf("Convert-VHD (.vhd to .vhdx for Gen 2): %w: %s", err, string(out))
	}
	return vhdxPath, nil
}

// CreateVM creates a Generation 2 Hyper-V VM with the given VHD and optional DVD, and ensures it has no network adapter.
func CreateVM(name, vhdPath, dvdPath string, memoryMB uint64, cpus int) error {
	memBytes := memoryMB * 1024 * 1024
	script := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
New-VM -Name %q -MemoryStartupBytes %d -Generation 2 -VHDPath %q
Set-VMProcessor -VMName %q -Count %d
`, name, memBytes, vhdPath, name, cpus)
	if dvdPath != "" {
		script += fmt.Sprintf(`
Add-VMDvdDrive -VMName %q -Path %q
`, name, dvdPath)
	}

	script += "\n"
	script += fmt.Sprintf(`Set-VMFirmware -VMName %q -EnableSecureBoot Off`, name) + "\n"
	logrus.Errorf("script: %s", script)
	out, err := runPowerShell(script)
	if err != nil {
		return fmt.Errorf("CreateVM: %w: %s", err, string(out))
	}
	return EnsureVMNoNetworkAdapter(name)
}

// EnsureVMNoNetworkAdapter removes any network adapters from the VM (New-VM may add one by default).
func EnsureVMNoNetworkAdapter(name string) error {
	script := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
$adapters = Get-VMNetworkAdapter -VMName %q -ErrorAction SilentlyContinue
if ($adapters) {
  $adapters | Remove-VMNetworkAdapter
}
`, name)
	out, err := runPowerShell(script)
	if err != nil {
		return fmt.Errorf("EnsureVMNoNetworkAdapter: %w: %s", err, string(out))
	}
	return nil
}

// StartVM starts the named Hyper-V VM.
func StartVM(name string) error {
	script := fmt.Sprintf(`Start-VM -Name %q`, name)
	out, err := runPowerShell(script)
	if err != nil {
		return fmt.Errorf("StartVM: %w: %s", err, string(out))
	}
	return nil
}

// StopVM stops the named Hyper-V VM (force stop).
func StopVM(name string) error {
	script := fmt.Sprintf(`Stop-VM -Name %q -Force -ErrorAction SilentlyContinue`, name)
	out, err := runPowerShell(script)
	if err != nil {
		return fmt.Errorf("StopVM: %w: %s", err, string(out))
	}
	return nil
}

// RemoveVM removes the named Hyper-V VM. The VM must be stopped first.
func RemoveVM(name string) error {
	script := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
$vm = Get-VM -Name %q -ErrorAction SilentlyContinue
if ($vm) {
  if ($vm.State -ne 'Off') { Stop-VM -Name %q -Force }
  Remove-VM -Name %q -Force
}
`, name, name, name)
	out, err := runPowerShell(script)
	if err != nil {
		return fmt.Errorf("RemoveVM: %w: %s", err, string(out))
	}
	return nil
}
