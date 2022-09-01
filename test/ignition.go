package e2e

import (
	"encoding/json"
	"net/url"
	"os"
)

var (
	mode    = 0644
	dirMode = 0744
	root    = "root"
	test    = "test"
	yes     = true
	no      = false
)

func CreateIgnition(ignitionFile string, publicKey string, user string, password string) error {

	linger := `[Unit]
Description=Activate podman socket
Wants=podman.socket
[Service]
ExecStart=/usr/bin/sleep infinity
`

	systemd := Systemd{
		Units: []Unit{
			{
				Name:    "systemd-resolved.service",
				Enabled: &no,
				Mask:    &yes,
			},
			{
				Name:    "podman.socket",
				Enabled: &yes,
			},
		},
	}

	passwd := Passwd{
		Users: []PasswdUser{
			{
				Name:         user,
				PasswordHash: &password,
				SSHAuthorizedKeys: []SSHAuthorizedKey{
					SSHAuthorizedKey(publicKey),
				},
				Groups: []Group{
					"wheel",
					"sudo",
				},
			},
			{
				Name:         "root",
				PasswordHash: &password,
				SSHAuthorizedKeys: []SSHAuthorizedKey{
					SSHAuthorizedKey(publicKey),
				},
			},
		},
	}

	storage := Storage{
		// Replaces resolv.conf with an empty file that will be overwritten by NetworkManager
		Files: []File{
			{
				Node: Node{
					Group:     NodeGroup{Name: &root},
					Path:      "/etc/resolv.conf",
					User:      NodeUser{Name: &root},
					Overwrite: &yes,
				},
				FileEmbedded1: FileEmbedded1{
					Contents: Resource{
						Source: encodeData(""),
					},
					Mode: &mode,
				},
			},
			{
				Node: Node{
					Group:     NodeGroup{Name: &test},
					Path:      "/home/" + test + "/.config/systemd/user/linger-podman.service",
					User:      NodeUser{Name: &test},
					Overwrite: &yes,
				},
				FileEmbedded1: FileEmbedded1{
					Contents: Resource{
						Source: encodeData(linger),
					},
					Mode: &mode,
				},
			},
			{
				Node: Node{
					Group:     NodeGroup{Name: &test},
					Path:      "/var/lib/systemd/linger/" + test,
					User:      NodeUser{Name: &test},
					Overwrite: &yes,
				},
				FileEmbedded1: FileEmbedded1{
					Contents: Resource{
						Source: encodeData(""),
					},
					Mode: &mode,
				},
			},
		},
		Directories: []Directory{
			dir("/home/" + test + "/.config"),
			dir("/home/" + test + "/.config/containers"),
			dir("/home/" + test + "/.config/systemd"),
			dir("/home/" + test + "/.config/systemd/user"),
			dir("/home/" + test + "/.config/systemd/user/default.target.wants"),
		},
		Links: []Link{
			{
				Node: Node{
					Group: NodeGroup{Name: &test},
					Path:  "/home/" + test + "/.config/systemd/user/default.target.wants/linger-podman.service",
					User:  NodeUser{Name: &test},
				},
				LinkEmbedded1: LinkEmbedded1{
					Hard:   &no,
					Target: "/home/" + test + "/.config/systemd/user/linger-podman.service",
				},
			},
		},
	}

	config := Config{
		Ignition: Ignition{Version: "3.2.0"},
		Systemd:  systemd,
		Passwd:   passwd,
		Storage:  storage,
	}

	contents, err := json.Marshal(config)
	if err != nil {
		return err
	}

	// #nosec
	return os.WriteFile(ignitionFile, contents, 0644)
}

func dir(path string) Directory {
	return Directory{
		Node: Node{
			Group: NodeGroup{Name: &test},
			Path:  path,
			User:  NodeUser{Name: &test},
		},
		DirectoryEmbedded1: DirectoryEmbedded1{Mode: &dirMode},
	}
}

func encodeData(data string) *string {
	str := "data:," + url.PathEscape(data)
	return &str
}
