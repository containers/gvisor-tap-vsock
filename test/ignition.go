package e2e

import (
	"encoding/json"
	"io/ioutil"
	"net/url"
)

func CreateIgnition(ignitionFile string, publicKey string, user string, password string) error {
	var (
		mode = 0644
		root = "root"
		yes  = true
		no   = false
	)

	systemd := Systemd{
		Units: []Unit{
			{
				Name:    "systemd-resolved.service",
				Enabled: &no,
				Mask:    &yes,
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
					Append: nil,
					Contents: Resource{
						Source: encodeData(""),
					},
					Mode: &mode,
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
	return ioutil.WriteFile(ignitionFile, contents, 0644)
}

func encodeData(data string) *string {
	str := "data:," + url.PathEscape(data)
	return &str
}
