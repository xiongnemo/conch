//go:build !linux

package tunroute

import "errors"

// Up is only implemented on Linux: elsewhere the kernels that need it are
// refused TUN before.
func Up(string) error {
	return errors.New("这个系统上 conch 还不能替内核配置 TUN 的路由")
}

// Down does nothing where Up cannot do anything.
func Down() error { return nil }
