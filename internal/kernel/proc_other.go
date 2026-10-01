//go:build !windows && !linux

package kernel

import "syscall"

// Other Unix systems have no parent-death signal; the daemon's pidfile
// check cleans up after a crash instead.
func setDeathSignal(*syscall.SysProcAttr) {}
