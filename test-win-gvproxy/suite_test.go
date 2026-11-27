//go:build windows

package e2e

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var (
	tmpDir        string
	binDir        string
	gvproxyBinary string
)

func TestSuite(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "gvproxy windows suite")
}

func init() {
	flag.StringVar(&tmpDir, "tmpDir", "../tmp", "temporary working directory")
	flag.StringVar(&binDir, "bin", "../bin", "directory with compiled binaries")
	_ = os.MkdirAll(tmpDir, 0o755)
	gvproxyBinary = filepath.Join(binDir, "gvproxy.exe")
}
