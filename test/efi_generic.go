//go:build !(darwin && arm64)

package e2e

func efiArgs() (string, error) {
	return "", nil
}
