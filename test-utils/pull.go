package e2eutils

import (
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/ulikunitz/xz"
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

func Decompress(localPath string) (string, error) {
	uncompressedPath := ""
	if strings.HasSuffix(localPath, ".xz") {
		uncompressedPath = strings.TrimSuffix(localPath, ".xz")
	} else if strings.HasSuffix(localPath, ".gz") {
		uncompressedPath = strings.TrimSuffix(localPath, ".gz")
	}

	if uncompressedPath == "" {
		return "", fmt.Errorf("unsupported compression for %s", localPath)
	}

	// we remove the uncompressed file if already exists. Maybe it has been used earlier and can affect the tests result
	os.Remove(uncompressedPath)

	uncompressedFileWriter, err := os.OpenFile(uncompressedPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return "", err
	}

	fmt.Printf("Extracting %s\n", localPath)
	if strings.HasSuffix(localPath, ".xz") {
		err = decompressXZ(localPath, uncompressedFileWriter)
	} else {
		err = decompressGZ(localPath, uncompressedFileWriter)
	}

	if err != nil {
		return "", err
	}
	return uncompressedPath, nil
}

func decompressXZ(src string, output io.Writer) error {
	file, err := os.Open(src)
	if err != nil {
		return err
	}
	defer file.Close()

	reader, err := xz.NewReader(file)
	if err != nil {
		return err
	}

	for {
		_, err := io.CopyN(output, reader, 1024*1024)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
	}
	return nil
}

func decompressGZ(src string, output io.Writer) error {
	file, err := os.Open(src)
	if err != nil {
		return err
	}
	defer file.Close()

	// Create a gzip reader
	reader, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer reader.Close()

	for {
		_, err := io.CopyN(output, reader, 1024)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
	}

	return nil
}
