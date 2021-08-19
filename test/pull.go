package e2e

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/sirupsen/logrus"
)

// DownloadVMImage downloads a VM image from url to given path
// with download status
func DownloadVMImage(downloadURL string, localImagePath string) error {
	fmt.Println("Downloading VM image: " + downloadURL)

	out, err := os.Create(localImagePath)
	if err != nil {
		return err
	}
	defer func() {
		if err := out.Close(); err != nil {
			logrus.Error(err)
		}
	}()

	// #nosec
	resp, err := http.Get(downloadURL)
	if err != nil {
		return err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logrus.Error(err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("error downloading VM image %s: %s", downloadURL, resp.Status)
	}

	if _, err := io.Copy(out, resp.Body); err != nil {
		return err
	}

	return nil
}

func Decompress(localPath, uncompressedPath string) error {
	uncompressedFileWriter, err := os.OpenFile(uncompressedPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}

	if !strings.HasSuffix(localPath, ".xz") {
		return fmt.Errorf("unsupported compression for %s", localPath)
	}

	fmt.Printf("Extracting %s\n", localPath)
	return decompressXZ(localPath, uncompressedFileWriter)
}

// Will error out if file without .xz already exists
// Maybe extracting then renameing is a good idea here..
// depends on xz: not pre-installed on mac, so it becomes a brew dependency
func decompressXZ(src string, output io.Writer) error {
	cmd := exec.Command("xzcat", "-T0", "-k", src)
	stdOut, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = os.Stderr
	go func() {
		if _, err := io.Copy(output, stdOut); err != nil {
			logrus.Error(err)
		}
	}()
	return cmd.Run()
}
