//go:build !linux && !darwin && !windows

package privilege

import "fmt"

func TUNError(string) error {
	return fmt.Errorf("%w：这个系统上 conch 还不能管理 TUN", ErrTUN)
}

func SetTUNCaps(string) error { return fmt.Errorf("只有 Linux 需要给内核设置权限") }

// RoutesError is for kernels conch routes TUN for, which run on Linux only.
func RoutesError() error { return nil }
