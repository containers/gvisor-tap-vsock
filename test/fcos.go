package e2e

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/opencontainers/go-digest"
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
