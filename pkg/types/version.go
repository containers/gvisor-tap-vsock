package types

import (
	"flag"
	"fmt"
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
	return fmt.Sprintf("%s version %s", ver.binaryName, gitVersion)
}

func (ver *version) AddFlag() {
	flag.BoolVar(&ver.showVersion, "version", false, "Print version information")
}

func (ver *version) ShowVersion() bool {
	return ver.showVersion
}
