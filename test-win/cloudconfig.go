//go:build windows

package e2ewin

import (
	"bytes"
	"fmt"
	"mime/multipart"
	"net/textproto"

	"go.yaml.in/yaml/v3"
)

type User struct {
	Name    string   `yaml:"name"`
	Sudo    string   `yaml:"sudo"`
	Shell   string   `yaml:"shell"`
	Groups  []string `yaml:"groups"`
	SSHKeys []string `yaml:"ssh_authorized_keys"`
	PasswordHash string `yaml:"passwd"`
	LockPassword bool `yaml:"lock_passwd"`
}

type WriteFile struct {
	Path        string `yaml:"path,omitempty"`
	Content     string `yaml:"content,omitempty"`
	Encoding    string `yaml:"encoding,omitempty"`
	Owner       string `yaml:"owner,omitempty"`
	Permissions string `yaml:"permissions,omitempty"`
}

type UserData struct {
	Users      []User      `yaml:"users"`
	WriteFiles []WriteFile `yaml:"write_files,omitempty"`
	RunCmd     []string    `yaml:"runcmd,omitempty"`
	Mounts     [][]string  `yaml:"mounts,omitempty"`
}

type EmbeddedResource struct {
	Name    string `yaml:"name"`
	Content []byte `yaml:"content"`
}

func defaultUserData(publicKey, ignitionUser, ignitionPasswordHash string) (*UserData, error) {
	
	return &UserData{
		Users: []User{
			{
				Name:    ignitionUser,
				Sudo:    "ALL=(ALL) NOPASSWD:ALL",
				Shell:   "/bin/bash",
				PasswordHash: ignitionPasswordHash,
				Groups:  []string{"users"},
				SSHKeys: []string{publicKey},
				LockPassword: false,
			},
		},
	}, nil
}

func (userData *UserData) Marshal() ([]byte, error) {
	data, err := yaml.Marshal(userData)
	if err != nil {
		return nil, err
	}

	headerLine := "#cloud-config\n"
	data = append([]byte(headerLine), data...)

	return data, nil
}

func (userData *UserData) MarshalMultiPart(extraData []byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	writer := multipart.NewWriter(buf)

	userDataBytes, err := userData.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshall user-data: %w", err)
	}

	// add our configuration as the first part
	if err := createCloudConfigPart(writer, userDataBytes); err != nil {
		return nil, fmt.Errorf("failed to create internal cloud-config part: %w", err)
	}

	// Add the user's config as a second part
	if err := createCloudConfigPart(writer, extraData); err != nil {
		return nil, fmt.Errorf("failed to create user cloud-config part: %w", err)
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to close multipart writer: %w", err)
	}

	// finalize mime archive with top-level header
	finalContent := new(bytes.Buffer)
	topLevelHeader := fmt.Sprintf("Content-Type: multipart/mixed; boundary=%s\nMIME-Version: 1.0\n\n", writer.Boundary())
	finalContent.WriteString(topLevelHeader)
	finalContent.Write(buf.Bytes())

	return finalContent.Bytes(), nil
}

func createCloudConfigPart(writer *multipart.Writer, content []byte) error {
	header := textproto.MIMEHeader{}
	// Set the specific Content-Type that cloud-init recognizes for configuration files
	header.Set("Content-Type", "text/cloud-config")
	header.Set("Merge-Type", "list(append)+dict(no_replace,recurse_list)+str()")

	partWriter, err := writer.CreatePart(header)
	if err != nil {
		return fmt.Errorf("failed to create new MIME part: %w", err)
	}

	if _, err := partWriter.Write(content); err != nil {
		return fmt.Errorf("failed to write content to MIME part: %w", err)
	}
	return nil
}
