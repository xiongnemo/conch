package kernel

import (
	"os"
	"strconv"
	"strings"
)

// readPidFile reads what Spec.PidFile recorded.
func readPidFile(path string) (int, string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, "", false
	}
	pidText, bin, _ := strings.Cut(strings.TrimSpace(string(data)), "\n")
	pid, err := strconv.Atoi(pidText)
	return pid, strings.TrimSpace(bin), err == nil && pid > 0
}
