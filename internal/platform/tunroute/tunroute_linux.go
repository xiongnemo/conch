package tunroute

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// run executes ip(8); tests replace it.
var run = func(args ...string) error {
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s：%v %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// deviceUp waits for the kernel to create the device; tests replace it.
var deviceUp = func(dev string) error {
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		if _, err := os.Stat(filepath.Join("/sys/class/net", dev)); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("TUN 网卡 %s 没有出现", dev)
		}
	}
}

// Up routes the system's default traffic into dev, replacing what an
// earlier Up left. IPv6 follows when the system has it.
func Up(dev string) error {
	if err := deviceUp(dev); err != nil {
		return err
	}
	if err := run("link", "set", "dev", dev, "up"); err != nil {
		return err
	}
	// Replies come back through the device for addresses the main table
	// routes elsewhere: strict reverse-path filtering would drop them.
	os.WriteFile(filepath.Join("/proc/sys/net/ipv4/conf", dev, "rp_filter"), []byte("2"), 0o644)
	table, mark := strconv.Itoa(Table), "0x"+strconv.FormatInt(Mark, 16)
	rules := []struct {
		prio int
		args []string
	}{
		{Priority, []string{"fwmark", mark, "lookup", "main"}}, // the kernel's own packets
		// DNS, wherever it goes (often the LAN's router): the kernel answers it.
		{Priority + 1, []string{"ipproto", "udp", "dport", "53", "lookup", table}},
		{Priority + 2, []string{"ipproto", "tcp", "dport", "53", "lookup", table}},
		{Priority + 3, []string{"lookup", "main", "suppress_prefixlength", "0"}}, // the LAN, VPNs: as they are
		{Priority + 4, []string{"lookup", table}},                                // the rest: into the device
	}
	for _, family := range []string{"-4", "-6"} {
		removeRules(family)
		err := run(family, "route", "replace", "default", "dev", dev, "table", table)
		for _, r := range rules {
			if err != nil {
				break
			}
			err = run(append([]string{family, "rule", "add", "priority", strconv.Itoa(r.prio)}, r.args...)...)
		}
		if err != nil {
			removeRules(family)
			run(family, "route", "flush", "table", table)
			if family == "-4" {
				return fmt.Errorf("把系统路由指向 TUN：%w", err)
			}
			// No IPv6 here: IPv4 is set up, which is what matters.
		}
	}
	return nil
}

// Down removes what Up added. The device goes away with the kernel.
func Down() error {
	for _, family := range []string{"-4", "-6"} {
		removeRules(family)
		run(family, "route", "flush", "table", strconv.Itoa(Table))
	}
	return nil
}

func removeRules(family string) {
	for i := range 5 {
		for run(family, "rule", "del", "priority", strconv.Itoa(Priority+i)) == nil {
		}
	}
}
