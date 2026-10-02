//go:build !windows

package kernel

import (
	"os"
	"syscall"
	"time"
)

// KillOrphan ends the kernel pidFile records if it still runs: a daemon
// that died without stopping it leaves it holding the ports (macOS has no
// parent-death signal, and Linux drops it for binaries with file
// capabilities). Only a process running the recorded binary is touched,
// not another that got the same pid since. It reports whether one was.
func KillOrphan(pidFile string) bool {
	pid, bin, ok := readPidFile(pidFile)
	os.Remove(pidFile)
	if !ok || syscall.Kill(pid, 0) != nil || !runs(pid, bin) {
		return false
	}
	syscall.Kill(pid, syscall.SIGTERM)
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if syscall.Kill(pid, 0) != nil {
			return true
		}
	}
	syscall.Kill(pid, syscall.SIGKILL)
	return true
}
