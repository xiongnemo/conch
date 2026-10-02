// Package sysproxy points the operating system's proxy settings at the
// local proxy port and puts the previous settings back afterwards. It must
// run in the user's session: system proxy settings are per user.
package sysproxy

import (
	"errors"
	"os/exec"
	"strings"
)

// Snapshot is the previous configuration, opaque to callers; store it so
// a crash can be repaired on the next start.
type Snapshot string

// Status describes the current OS setting.
type Status struct {
	Enabled bool   `json:"enabled"`
	Server  string `json:"server,omitempty"` // host:port of the HTTP proxy
}

// ErrUnsupported means this desktop has no setting conch knows how to change.
var ErrUnsupported = errors.New("没法自动设置这个桌面环境的系统代理；请在应用里手动设置 HTTP/SOCKS5 代理，或使用 conch run -- <命令>")

// Bypass lists destinations that should never go through the proxy.
var Bypass = []string{"localhost", "127.0.0.0/8", "::1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "*.local"}

// runner runs a command and returns its output; tests replace it.
type runner func(name string, args ...string) (string, error)

func execRun(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

var run runner = execRun

// Enable points the system proxy at 127.0.0.1:port and returns what was
// configured before.
func Enable(port int) (Snapshot, error) { return enable(port) }

// Restore puts back a snapshot taken by Enable.
func Restore(s Snapshot) error { return restore(s) }

// Current reports the current system proxy setting.
func Current() (Status, error) { return current() }
