package e2eutils

import (
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/sirupsen/logrus"
)

type decompressMeta struct {
	CompressedSHA256 string `json:"compressed_sha256"`
	UncompressedSize int64  `json:"uncompressed_size"`
}

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

// DownloadVMImageIfMissing downloads the VM image only when localImagePath is missing or empty.
// A non-empty existing file is treated as a valid cached copy to speed up repeated test runs.
func DownloadVMImageIfMissing(downloadURL string, localImagePath string) error {
	if fi, err := os.Stat(localImagePath); err == nil && fi.Size() > 0 {
		logrus.Infof("Using cached VM image archive %s (%d bytes)", localImagePath, fi.Size())
		return nil
	}
	return DownloadVMImage(downloadURL, localImagePath)
}

func decompressMetaPath(compressedPath string) string {
	return compressedPath + ".decompress_meta"
}

func sha256OfFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func readDecompressMeta(path string) (decompressMeta, error) {
	var m decompressMeta
	b, err := os.ReadFile(path)
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, err
	}
	return m, nil
}

func writeDecompressMeta(path string, m decompressMeta) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0600)
}

func uncompressedPathForArchive(localPath string) (string, error) {
	switch {
	case strings.HasSuffix(localPath, ".xz"):
		return strings.TrimSuffix(localPath, ".xz"), nil
	case strings.HasSuffix(localPath, ".gz"):
		return strings.TrimSuffix(localPath, ".gz"), nil
	case strings.HasSuffix(localPath, ".zip"):
		return strings.TrimSuffix(localPath, ".zip"), nil
	default:
		return "", fmt.Errorf("unsupported compression for %s", localPath)
	}
}

// Decompress unpacks a compressed VM image when the output is missing or does not match
// the cached metadata for this archive (SHA-256 of the compressed file + uncompressed size).
// That keeps repeated test runs fast while ensuring a full re-extract after archive updates
// or failed/partial unpacks.
func Decompress(localPath string) (string, error) {
	uncompressedPath, err := uncompressedPathForArchive(localPath)
	if err != nil {
		return "", err
	}

	metaPath := decompressMetaPath(localPath)
	sha, err := sha256OfFile(localPath)
	if err != nil {
		return "", err
	}

	if fi, err := os.Stat(uncompressedPath); err == nil {
		meta, rerr := readDecompressMeta(metaPath)
		if rerr == nil && meta.CompressedSHA256 == sha && meta.UncompressedSize == fi.Size() {
			logrus.Infof("Using cached uncompressed image %s (%d bytes)", uncompressedPath, fi.Size())
			return uncompressedPath, nil
		}
	}

	_ = os.Remove(uncompressedPath)
	_ = os.Remove(metaPath)

	uncompressedFileWriter, err := os.OpenFile(uncompressedPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return "", err
	}

	fmt.Printf("Extracting %s\n", localPath)
	switch {
	case strings.HasSuffix(localPath, ".xz"):
		finished := make(chan bool)
		err = decompressXZ(localPath, uncompressedFileWriter, finished)
		<-finished
	case strings.HasSuffix(localPath, ".gz"):
		err = decompressGZ(localPath, uncompressedFileWriter)
	case strings.HasSuffix(localPath, ".zip"):
		err = decompressZip(localPath, uncompressedFileWriter)
	}

	if err != nil {
		return "", err
	}

	closeErr := uncompressedFileWriter.Close()
	if closeErr != nil {
		_ = os.Remove(uncompressedPath)
		return "", closeErr
	}

	outFi, err := os.Stat(uncompressedPath)
	if err != nil {
		return "", err
	}
	if err := writeDecompressMeta(metaPath, decompressMeta{
		CompressedSHA256: sha,
		UncompressedSize: outFi.Size(),
	}); err != nil {
		_ = os.Remove(metaPath)
		return "", fmt.Errorf("could not write decompress metadata: %v", err)
	}
	return uncompressedPath, nil
}

// Will error out if file without .xz already exists
// Maybe extracting then renameing is a good idea here..
// depends on xz: not pre-installed on mac, so it becomes a brew dependency
func decompressXZ(src string, output io.Writer, finished chan bool) error {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		// find the root of the repository
		wd, _ := os.Getwd()
		wd = strings.SplitAfter(wd, "gvisor-tap-vsock")[0]
		gxz := filepath.Join(wd, "tools", "bin", "gxz.exe")
		cmd = exec.Command(gxz, "-d", "-c", src)
	} else {
		cmd = exec.Command("xzcat", "-T0", "-k", src)
	}
	stdOut, err := cmd.StdoutPipe()
	if err != nil {
		finished <- false
		return err
	}
	cmd.Stderr = os.Stderr
	go func() {
		if _, err := io.Copy(output, stdOut); err != nil {
			logrus.Error(err)
		}
		finished <- true
	}()
	return cmd.Run()
}

// streamCopy copies src to dst in fixed-size chunks. Using io.CopyN instead of
// io.Copy satisfies gosec G110 for readers from decompression APIs.
func streamCopy(dst io.Writer, src io.Reader) error {
	const chunkSize = 1024 * 1024
	for {
		_, err := io.CopyN(dst, src, chunkSize)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
	}
	return nil
}

func decompressZip(src string, output io.Writer) error {
	zipReader, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer zipReader.Close()
	for _, file := range zipReader.File {
		rc, err := file.Open()
		if err != nil {
			return err
		}
		err = streamCopy(output, rc)
		if closeErr := rc.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
		if err != nil {
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
