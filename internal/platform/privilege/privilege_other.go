//go:build !linux && !darwin && !windows

package privilege

import "fmt"

func TUNError(string) error {
	return fmt.Errorf("%w：这个系统上 nautilus 还不能管理 TUN", ErrTUN)
}

func SetTUNCaps(string) error { return fmt.Errorf("只有 Linux 需要给内核设置权限") }
