//go:build darwin

package e2evfkit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"strings"

	e2e "github.com/containers/gvisor-tap-vsock/test"
	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
)

var _ = ginkgo.Describe("connectivity with vfkit", func() {
	e2e.BasicConnectivityTests(e2e.BasicTestProps{
		SSHExec: sshExec,
	})
})

var _ = ginkgo.Describe("dns with vfkit", func() {
	e2e.BasicDNSTests(e2e.BasicTestProps{
		SSHExec: sshExec,
		Sock:    sock,
	})
})

var _ = ginkgo.Describe("dhcp with vfkit", func() {
	e2e.BasicDHCPTests(e2e.BasicTestProps{
		SSHExec: sshExec,
		Sock:    sock,
	})
})

var _ = ginkgo.Describe("upload and download with vfkit", func() {
	tmpDir, err := os.MkdirTemp("", "vfkit")
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	sumMap := make(map[string]string)
	dstDir := "/tmp"
	ginkgo.AfterEach(func() {
		err := os.RemoveAll(tmpDir)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})
	ginkgo.It("should upload 1MB, 10MB, and 100MB files to vfkit", func() {
		for _, size := range []int{6, 7, 8} {
			file, err := os.CreateTemp(tmpDir, "testfile")
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			err = file.Truncate(int64(math.Pow10(size)))
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			hasher := sha256.New()
			_, err = io.Copy(hasher, file)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			srcPath := file.Name()
			dstPath := filepath.Join(dstDir, path.Base(srcPath))

			err = scpToVM(srcPath, dstDir)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			out, err := sshExec(fmt.Sprintf("sha256sum %s | awk '{print $1}'", dstPath))
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			localSum := hex.EncodeToString(hasher.Sum(nil))
			vmSum := strings.TrimSpace(string(out))
			gomega.Expect(vmSum).To(gomega.Equal(localSum))

			sumMap[dstPath] = vmSum
		}
	})
	ginkgo.It("should download the uploaded files from vfkit", func() {
		// Download the uploaded files
		dlTmpDir, err := os.MkdirTemp("", "vfkit-dl")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		for filename := range sumMap {
			err = scpFromVM(filename, dlTmpDir)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		}

		dir, err := os.ReadDir(dlTmpDir)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		for _, entry := range dir {
			hasher := sha256.New()
			file, err := os.Open(filepath.Join(dlTmpDir, entry.Name()))
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			_, err = io.Copy(hasher, file)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			gomega.Expect(hasher.Sum(nil)).NotTo(gomega.Equal(sumMap[entry.Name()]))

		}
		// Set tmpDir to dlTmpDir for cleanup in AfterEach
		tmpDir = dlTmpDir
	})
})
var _ = ginkgo.Describe("ping with gvproxy and vfkit", func() {
	ginkgo.It("should succeed to ping a known domain", func() {
		_, err := sshExec("ping -w2 crc.dev")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})
	ginkgo.It("should fail to ping an unknown domain", func() {
		_, err := sshExec("ping -w2 unknown.crc.dev")
		gomega.Expect(err).To(gomega.HaveOccurred())
	})
	ginkgo.It("should succeed to ping a known IP", func() {
		_, err := sshExec("ping -w2 1.1.1.1")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})
	ginkgo.It("should fail to ping an unknown IP", func() {
		_, err := sshExec("ping -w2 7.7.7.7")
		// FIXME: This should be:
		// gomega.Expect(err).To(gomega.HaveOccurred())
		// but this is currently not working as expected:
		// https://github.com/containers/gvisor-tap-vsock/issues/428
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})
})
