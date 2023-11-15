package types

import (
	"flag"
	"fmt"
	"runtime/debug"
)

var (
	// set using the '-X github.com/containers/gvisor-tap-vsock/pkg/types.gitVersion' linker flag
	gitVersion = ""
)

type version struct {
	binaryName  string
	showVersion bool
}

func NewVersion(binaryName string) *version { //nolint:revive
	return &version{
		binaryName: binaryName,
	}
}

func (ver *version) String() string {
	return fmt.Sprintf("%s version %s", ver.binaryName, moduleVersion())
}

func (ver *version) AddFlag() {
	flag.BoolVar(&ver.showVersion, "version", false, "Print version information")
}

func (ver *version) ShowVersion() bool {
	return ver.showVersion
}

func moduleVersion() string {
	switch {
	// This will be set when building from git using make
	case gitVersion != "":
		return gitVersion
	// moduleVersionFromBuildInfo() will be set when using `go install`
	default:
		return moduleVersionFromBuildInfo()
	}
}

func moduleVersionFromBuildInfo() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	if info.Main.Version == "(devel)" {
		return ""
	}
	return info.Main.Version
}
