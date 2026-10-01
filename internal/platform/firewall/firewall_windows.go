package firewall

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"golang.org/x/sys/windows"
)

// Allow lets program accept inbound connections, under a rule named after
// the kernel that follows it to new paths (kernel upgrades). It needs
// administrator rights, which TUN needs anyway.
func Allow(kernel, program string) error {
	if !known(kernel) {
		return fmt.Errorf("不认识的内核 %q", kernel)
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("需要管理员权限")
	}
	name := ruleName(kernel)
	exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+name).Run()
	out, err := exec.Command("netsh", "advfirewall", "firewall", "add", "rule", "name="+name,
		"dir=in", "action=allow", "program="+program, "enable=yes").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v：%s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Remove deletes the rules Allow added.
func Remove() {
	for _, k := range kernels {
		exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+ruleName(k)).Run()
	}
}
