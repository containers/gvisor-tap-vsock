//go:build !(darwin && arm64)

package e2eqemu

func efiArgs() (string, error) {
	return "", nil
}
