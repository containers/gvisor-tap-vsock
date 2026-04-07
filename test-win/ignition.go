//go:build windows

package e2ewin

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kdomanski/iso9660"
	"github.com/sirupsen/logrus"
)

const HyperVVsockNMConnection = `[connection]
id=vsock0
type=tun
interface-name=vsock0

[tun]
mode=2

[802-3-ethernet]
cloned-mac-address=5A:94:EF:E4:0C:EE

[ipv4]
method=auto

[proxy]
`

func CreateCloudInit(publicKey, ignitionUser, ignitionPasswordHash string, netPort uint64, binaryPath string, tmpDir string) (string, error) {
	writer, err := iso9660.NewWriter()
	if err != nil {
		return "", fmt.Errorf("failed to create writer: %w", err)
	}

	defer func() {
		if err := writer.Cleanup(); err != nil {
			logrus.Error(err)
		}
	}()

	metadata, networkConfig := []byte{}, []byte{}

	userdata, err := generateUserData(publicKey, ignitionUser, ignitionPasswordHash, netPort, binaryPath)
	if err != nil {
		return "", fmt.Errorf("failed to generate user-data file: %w", err)
	}

	if err := writer.AddFile(bytes.NewReader(userdata), "user-data"); err != nil {
		return "", err
	}
	if err := writer.AddFile(bytes.NewReader(metadata), "meta-data"); err != nil {
		return "", err
	}
	if err := writer.AddFile(bytes.NewReader(networkConfig), "network-config"); err != nil {
		return "", err
	}

	resources := GetEmbeddedResources(binaryPath)
	for _, res := range resources {
		if err := writer.AddFile(bytes.NewReader(res.Content), res.Name); err != nil {
			return "", err
		}
	}

	isoFilePath, err := GetCloudInitISOVMFile(tmpDir)
	if err != nil {
		return "", fmt.Errorf("failed to create cloud-init ISO file path: %w", err)
	}

	isoFile, err := os.Create(isoFilePath)
	if err != nil {
		return "", fmt.Errorf("unable to create cloud-init ISO file: %w", err)
	}

	defer func() {
		if err := isoFile.Close(); err != nil {
			logrus.Error(fmt.Errorf("failed to close cloud-init ISO file: %w", err))
		}
	}()

	err = writer.WriteTo(isoFile, "cidata")
	if err != nil {
		os.Remove(isoFile.Name())
		return "", fmt.Errorf("failed to write cloud-init ISO image: %w", err)
	}

	return isoFilePath, nil
}

func GetEmbeddedResources(binaryPath string) []EmbeddedResource {

	extraFiles := []EmbeddedResource{}
	gvforwarderBytes, err := getGvForwarderBytes(binaryPath)
	if err != nil {
		logrus.Errorf("Failed to get gvforwarder: %v", err)
		return extraFiles
	}
	extraFiles = append(extraFiles, EmbeddedResource{
		Name:    "gvforwarder",
		Content: gvforwarderBytes,
	})
	return extraFiles
}

func GetCloudInitISOVMFile(tmpDir string) (string, error) {
	return filepath.Abs(filepath.Join(tmpDir, "cloudinit.iso"))
}

func generateUserData(publicKey, ignitionUser, ignitionPasswordHash string, netPort uint64, binaryPath string) ([]byte, error) {
	userData, err := defaultUserData(publicKey, ignitionUser, ignitionPasswordHash)
	if err != nil {
		return nil, fmt.Errorf("failed to generate user-data file: %w", err)
	}
	_ = addUserModeNetworking(userData, netPort)
	return userData.Marshal()
}

func addUserModeNetworking(userData *UserData, netPort uint64) error {
	netUnitFile, err := CreateNetworkUnitWithBinary("/usr/local/bin/gvforwarder", netPort)
	if err != nil {
		return err
	}

	userData.WriteFiles = []WriteFile{
		{
			Path:        "/etc/NetworkManager/system-connections/vsock0.nmconnection",
			Content:     HyperVVsockNMConnection,
			Permissions: "0600",
			Owner:       "root",
		},
		{
			Path:        "/etc/systemd/system/vsock-network.service",
			Content:     netUnitFile,
			Permissions: "0644",
			Owner:       "root",
		},
	}

	userData.RunCmd = []string{
		"install -o root -g root -m 0755 /mnt/gvforwarder /usr/local/bin/gvforwarder",
		"nmcli connection reload",
		"systemctl daemon-reload",
		"systemctl enable --now vsock-network.service",
	}

	userData.Mounts = [][]string{
		{"/dev/sr0", "/mnt", "iso9660", "defaults,ro", "0", "0"},
	}

	return nil
}

func CreateNetworkUnitWithBinary(binaryPath string, netPort uint64) (string, error) {
	netUnit := `[Unit]
Description=vsock_network
After=NetworkManager.service

[Service]
ExecStart=` + fmt.Sprintf("%s -preexisting -iface vsock0 -url vsock://2:%d/connect", binaryPath, netPort) + `
ExecStartPost=/usr/bin/nmcli c up vsock0

[Install]
WantedBy=multi-user.target`

	return netUnit, nil
}

func getGvForwarderBytes(binaryPath string) ([]byte, error) {
	gvforwarderBytes, err := os.ReadFile(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read gvforwarder binary: %w", err)
	}
	return gvforwarderBytes, nil
}
