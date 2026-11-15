package service

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

// Autostart starts `conch daemon` when the user logs in, as the user and
// without admin rights: what the user would run by hand, with their own
// profile, kernels and password. It cannot use TUN (except on Linux
// after `conch kernel setcap`), which needs the system service.
type Autostart struct {
	Bin     string // the conch binary
	Profile string // the profile, an absolute path
	// Dir is where the OS looks for what starts at login: the systemd
	// user units' directory on Linux, ~/Library/LaunchAgents on macOS.
	// Unused on Windows, where it is the registry.
	Dir string
	// AutostartDir is ~/.config/autostart, used on Linux without a
	// systemd user session.
	AutostartDir string
	UID          string // macOS: the user's launchd domain
	LogFile      string // macOS: where the daemon's output goes
	Run          Runner
	Log          io.Writer
}

// ErrAutostartOff means autostart is not set up.
var ErrAutostartOff = errors.New("没有开启登录时自动启动")

// LaunchdUser is the label of the daemon started at login on macOS.
const LaunchdUser = "io.github.xiongnemo.conch.user"

// Args is the command started at login. The daemon runs in the
// profile's directory, as it would from a terminal there, so .env and
// managed.yaml next to the profile are found.
func (a Autostart) Args() []string {
	return []string{a.Bin, "daemon", "--autostart", "--chdir", filepath.Dir(a.Profile), "--profile", a.Profile}
}

func (a Autostart) logf(format string, args ...any) {
	if a.Log != nil {
		fmt.Fprintf(a.Log, format+"\n", args...)
	}
}

// SystemdUserUnit runs the daemon in the user's systemd session.
func SystemdUserUnit(a Autostart) string {
	args := a.Args()
	quoted := make([]string, len(args))
	for i, s := range args {
		quoted[i] = systemdQuote(s)
	}
	return fmt.Sprintf(`# Installed by conch autostart on.
[Unit]
Description=Conch proxy daemon
After=network-online.target

[Service]
Type=simple
ExecStart=%s
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
`, strings.Join(quoted, " "))
}

// DesktopEntry starts the daemon with the desktop session, for Linux
// systems without a systemd user session.
func DesktopEntry(a Autostart) string {
	args := a.Args()
	quoted := make([]string, len(args))
	for i, s := range args {
		quoted[i] = desktopQuote(s)
	}
	return fmt.Sprintf(`# Installed by conch autostart on.
[Desktop Entry]
Type=Application
Name=Conch
Comment=Conch proxy daemon
Exec=%s
Terminal=false
NoDisplay=true
X-GNOME-Autostart-enabled=true
`, strings.Join(quoted, " "))
}

// desktopQuote quotes an argument of a desktop entry's Exec key.
func desktopQuote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\n\"'\\><~|&;$*?#()`%=") {
		return s
	}
	r := strings.NewReplacer(`\`, `\\\\`, `"`, `\\"`, "`", "\\\\`", `$`, `\\$`, `%`, `%%`)
	return `"` + r.Replace(s) + `"`
}

// LaunchdUserPlist runs the daemon in the user's launchd session.
func LaunchdUserPlist(a Autostart) string {
	return plist(LaunchdUser, a.Args(), filepath.Dir(a.Profile), a.LogFile)
}
