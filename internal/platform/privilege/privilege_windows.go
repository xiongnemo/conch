package privilege

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// TUNError returns nil if nautilus runs elevated, which creating a wintun
// adapter requires.
func TUNError(string) error {
	if windows.GetCurrentProcessToken().IsElevated() {
		return nil
	}
	return fmt.Errorf("%w：需要管理员权限，可以以管理员身份运行，或者用 nautilus service install 安装成 Windows 服务", ErrTUN)
}

func SetTUNCaps(string) error { return fmt.Errorf("只有 Linux 需要给内核设置权限") }
