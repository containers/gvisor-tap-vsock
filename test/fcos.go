package e2e

import (
	"os"
	"path/filepath"
	"strings"

	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"

	"github.com/opencontainers/go-digest"

	"github.com/coreos/stream-metadata-go/fedoracoreos"
	"github.com/coreos/stream-metadata-go/stream"
	"github.com/sirupsen/logrus"
)

type FcosDownload struct {
	DataDir string
}

type fcosDownloadInfo struct {
	Location  string
	Sha256Sum string
}

func NewFcosDownloader(dataDir string) (*FcosDownload, error) {
	return &FcosDownload{
		DataDir: dataDir,
	}, nil
}

func imageName(info *fcosDownloadInfo) string {
	urlSplit := strings.Split(info.Location, "/")
	return urlSplit[len(urlSplit)-1]
}

func (downloader *FcosDownload) DownloadImage() (string, error) {
	info, err := getFCOSDownload()
	if err != nil {
		return "", err
	}

	compressedImage := filepath.Join(downloader.DataDir, imageName(info))
	uncompressedImage := strings.TrimSuffix(filepath.Join(filepath.Dir(compressedImage), imageName(info)), ".xz")

	// check if the latest image is already present
	ok, err := downloader.updateAvailable(info, compressedImage)
	if err != nil {
		return "", err
	}
	if !ok {
		if err := DownloadVMImage(info.Location, compressedImage); err != nil {
			return "", err
		}
	}

	if _, err := os.Stat(uncompressedImage); err == nil {
		return uncompressedImage, nil
	}
	if err := Decompress(compressedImage, uncompressedImage); err != nil {
		return "", err
	}
	return uncompressedImage, nil
}

func (downloader *FcosDownload) updateAvailable(info *fcosDownloadInfo, compressedImage string) (bool, error) {
	//	 check the sha of the local image if it exists
	//  get the sha of the remote image
	// == dont bother to pull
	if _, err := os.Stat(compressedImage); os.IsNotExist(err) {
		return false, nil
	}
	fd, err := os.Open(compressedImage)
	if err != nil {
		return false, err
	}
	defer fd.Close()
	sum, err := digest.SHA256.FromReader(fd)
	if err != nil {
		return false, err
	}
	if sum.Encoded() == info.Sha256Sum {
		return true, nil
	}
	return false, nil
}

// as of 2024-05-28, these are the 4 architectures available in
// curl https://builds.coreos.fedoraproject.org/streams/next.json
func coreosArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	case "ppc64le":
		return "ppc64le"
	case "s390x":
		return "s390x"
	}
	panic(fmt.Sprintf("unknown arch: %s", runtime.GOOS))
}

// This should get Exported and stay put as it will apply to all fcos downloads
// getFCOS parses fedoraCoreOS's stream and returns the image download URL and the release version
func getFCOSDownload() (*fcosDownloadInfo, error) {
	streamurl := fedoracoreos.GetStreamURL(fedoracoreos.StreamNext)
	resp, err := http.Get(streamurl.String())
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logrus.Error(err)
		}
	}()

	var fcosstable stream.Stream
	if err := json.Unmarshal(body, &fcosstable); err != nil {
		return nil, err
	}
	arch, ok := fcosstable.Architectures[coreosArch()]
	if !ok {
		return nil, fmt.Errorf("unable to pull VM image: no targetArch in stream")
	}
	artifacts := arch.Artifacts
	if artifacts == nil {
		return nil, fmt.Errorf("unable to pull VM image: no artifact in stream")
	}
	qemu, ok := artifacts["qemu"]
	if !ok {
		return nil, fmt.Errorf("unable to pull VM image: no qemu artifact in stream")
	}
	formats := qemu.Formats
	if formats == nil {
		return nil, fmt.Errorf("unable to pull VM image: no formats in stream")
	}
	qcow, ok := formats["qcow2.xz"]
	if !ok {
		return nil, fmt.Errorf("unable to pull VM image: no qcow2.xz format in stream")
	}
	disk := qcow.Disk
	if disk == nil {
		return nil, fmt.Errorf("unable to pull VM image: no disk in stream")
	}
	return &fcosDownloadInfo{
		Location:  disk.Location,
		Sha256Sum: disk.Sha256,
	}, nil
}
