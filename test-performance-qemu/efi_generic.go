//go:build !(darwin && arm64)

package e2e_performance_qemu

func efiArgs() ([]string, error) {
	return nil, nil
}
