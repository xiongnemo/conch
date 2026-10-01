// Package sysdns points the system resolver at an address the TUN device
// captures, where the kernel cannot capture DNS on its own, and puts the
// previous settings back afterwards.
//
// On macOS the resolver usually asks the router, which is on the local
// network and so routed around the TUN device: queries would leak and
// fake-ip would not work. Linux and Windows need nothing.
package sysdns

import (
	"os/exec"
	"strings"
)

// Snapshot is the previous configuration, opaque to callers; store it so
// a crash can be repaired on the next start.
type Snapshot string

type runner func(name string, args ...string) (string, error)

func execRun(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// Needed reports whether TUN needs the system resolver redirected here.
func Needed() bool { return needed }

// Enable points the system resolver at server and returns what was set before.
func Enable(server string) (Snapshot, error) { return enable(server) }

// Restore puts back a snapshot taken by Enable.
func Restore(s Snapshot) error { return restore(s) }
