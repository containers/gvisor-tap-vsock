//go:build windows

package e2ewin

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo"

	e2e "github.com/containers/gvisor-tap-vsock/test"
	"github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

func sshExec(cmd ...string) ([]byte, error) {
	out, err := sshCommand(cmd...).Output()
	if err != nil {
		// Convert ExitError with byte array stderr to readable error
		if exitErr, ok := err.(*exec.ExitError); ok && len(exitErr.Stderr) > 0 {
			return out, fmt.Errorf("%w\nStderr: %s", err, string(exitErr.Stderr))
		}
	}
	return out, err
}

func sshCommand(cmd ...string) *exec.Cmd {
	sshCmd := exec.Command("ssh",
		"-o", "UserKnownHostsFile="+os.DevNull,
		"-o", "StrictHostKeyChecking=no",
		"-o", "IdentitiesOnly=yes",
		"-i", privateKeyFile,
		"-p", strconv.Itoa(sshPort),
		fmt.Sprintf("%s@127.0.0.1", ignitionUser), "--", strings.Join(cmd, " ")) // #nosec G204
	return sshCmd
}

var _ = Describe("connectivity with Windows", func() {
	e2e.BasicConnectivityTests(e2e.BasicTestProps{
		SSHExec: sshExec,
	})
})

var _ = Describe("ping with gvproxy and vfkit", func() {
	It("should succeed to ping a known domain", func() {
		out, err := sshExec("ping -w2 crc.dev")
		log.Infof("ping: %s", out)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})
	It("should fail to ping an unknown domain", func() {
		out, err := sshExec("ping -w2 unknown.crc.dev")
		log.Infof("ping: %s", out)
		gomega.Expect(err).To(gomega.HaveOccurred())
	})
	It("should succeed to ping a known IP", func() {
		out, err := sshExec("ping -w2 1.1.1.1")
		log.Infof("ping: %s", out)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})
	It("should fail to ping an unknown IP", func() {
		out, err := sshExec("ping -w2 7.7.7.7")
		log.Infof("ping: %s", out)
		gomega.Expect(err).To(gomega.HaveOccurred())
	})
	It("should succeed to ping an localhost", func() {
		out, err := sshExec("ping -w2 127.0.0.1")
		log.Infof("ping: %s", out)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})
})
