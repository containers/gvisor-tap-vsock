package e2eutils

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func CreateSSHKeys(publicKeyFile, privateKeyFile string) (string, error) {
	_ = os.Remove(publicKeyFile)
	_ = os.Remove(privateKeyFile)
	err := exec.Command("ssh-keygen", "-N", "", "-t", "ed25519", "-f", privateKeyFile).Run()
	if err != nil {
		return "", fmt.Errorf("could not generate ssh keys: %w", err)
	}

	return readPublicKey(publicKeyFile)
}

func readPublicKey(publicKeyFile string) (string, error) {
	publicKey, err := os.ReadFile(publicKeyFile)
	if err != nil {
		return "", nil
	}

	return strings.TrimSpace(string(publicKey)), nil
}
