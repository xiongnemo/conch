package kernel

import "syscall"

// setDeathSignal kills the kernel if the daemon dies, so a crashed daemon
// never leaves an unsupervised proxy behind.
func setDeathSignal(a *syscall.SysProcAttr) {
	a.Pdeathsig = syscall.SIGTERM
}
