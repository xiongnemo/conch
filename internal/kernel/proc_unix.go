//go:build !windows

package kernel

import (
	"os/exec"
	"syscall"
)

func configureChild(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	setDeathSignal(cmd.SysProcAttr)
}

func afterStart(*exec.Cmd) {}

// terminate asks the kernel to exit cleanly; it closes its listeners and,
// for TUN, restores routes.
func terminate(cmd *exec.Cmd) {
	cmd.Process.Signal(syscall.SIGTERM)
}
