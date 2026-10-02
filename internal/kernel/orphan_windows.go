package kernel

import "os"

// KillOrphan has nothing to do on Windows: the Job Object the daemon puts
// its kernels in ends them when the daemon goes away.
func KillOrphan(pidFile string) bool {
	os.Remove(pidFile)
	return false
}
