package kernel

import (
	"os"
	"path/filepath"
	"strconv"
)

// runs reports whether process pid runs the binary at bin.
func runs(pid int, bin string) bool {
	exe, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if err != nil {
		return false
	}
	if real, err := filepath.EvalSymlinks(bin); err == nil {
		bin = real
	}
	return exe == bin
}
