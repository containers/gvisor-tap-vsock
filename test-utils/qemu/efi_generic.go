//go:build !(darwin && arm64)

package qemu

func efiArgs() ([]string, error) {
	return nil, nil
}
