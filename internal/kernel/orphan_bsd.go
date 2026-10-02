//go:build !windows && !linux

package kernel

import (
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// runs reports whether process pid runs the binary at bin, by the name ps
// gives its command.
func runs(pid int, bin string) bool {
	out, err := exec.Command("ps", "-o", "comm=", "-p", strconv.Itoa(pid)).Output()
	return err == nil && filepath.Base(strings.TrimSpace(string(out))) == filepath.Base(bin)
}
