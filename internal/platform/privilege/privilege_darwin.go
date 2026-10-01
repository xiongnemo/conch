package privilege

import (
	"fmt"
	"os"
)

// TUNError returns nil if nautilus runs as root, which macOS requires
// for creating utun devices and changing routes.
func TUNError(string) error {
	if os.Geteuid() == 0 {
		return nil
	}
	return fmt.Errorf("%w：macOS 上需要以 root 运行，可以用 sudo nautilus service install 安装成系统服务", ErrTUN)
}

func SetTUNCaps(string) error { return fmt.Errorf("只有 Linux 需要给内核设置权限") }
