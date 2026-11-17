package service

import (
	"errors"
	"fmt"
	"html"
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

// Registered is what autostart starts, as the OS has it registered: for
// `conch migrate`, which points it at the files' new places.
type Registered struct {
	Args    []string // the command, the conch binary first
	LogFile string   // macOS: where its output goes
	Where   string   // the file or registry value, for messages
}

// Profile is the profile the registered command runs with.
func (r Registered) Profile() string {
	for i, a := range r.Args {
		if a == "--profile" && i+1 < len(r.Args) {
			return r.Args[i+1]
		}
	}
	return ""
}

// Autostart is what to register instead: the same binary, with profile
// and logFile.
func (r Registered) Autostart(a Autostart, profile, logFile string) Autostart {
	if len(r.Args) > 0 {
		a.Bin = r.Args[0]
	}
	a.Profile, a.LogFile = profile, logFile
	return a
}

// splitQuoted splits a command line where arguments with spaces are in
// double quotes, inside which unquote undoes the escapes.
func splitQuoted(s string, unquote func(string) string) []string {
	var args []string
	for s = strings.TrimSpace(s); s != ""; s = strings.TrimSpace(s) {
		if s[0] != '"' {
			end := strings.IndexAny(s, " \t")
			if end < 0 {
				end = len(s)
			}
			args, s = append(args, s[:end]), s[end:]
			continue
		}
		end := 1
		for end < len(s) && s[end] != '"' {
			if s[end] == '\\' {
				end++
			}
			end++
		}
		args = append(args, unquote(s[1:min(end, len(s))]))
		s = s[min(end+1, len(s)):]
	}
	return args
}

// parseSystemdExec splits an ExecStart value as systemdQuote writes it.
func parseSystemdExec(s string) []string {
	return splitQuoted(s, strings.NewReplacer(`\\`, `\`, `\"`, `"`).Replace)
}

// parseDesktopExec splits an Exec value as desktopQuote writes it: the
// string escapes of desktop entries first, then the Exec key's quoting.
func parseDesktopExec(s string) []string {
	s = strings.NewReplacer(`\\`, `\`, `\s`, " ", `\n`, "\n", `\t`, "\t", `\r`, "\r").Replace(s)
	args := splitQuoted(s, strings.NewReplacer(`\"`, `"`, "\\`", "`", `\$`, `$`, `\\`, `\`).Replace)
	for i, a := range args {
		args[i] = strings.ReplaceAll(a, "%%", "%")
	}
	return args
}

// keyLine finds the value of key= in an ini-style file.
func keyLine(content, key string) (string, bool) {
	for _, l := range strings.Split(content, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), key+"="); ok {
			return v, true
		}
	}
	return "", false
}

// parsePlist reads the ProgramArguments and StandardOutPath of a plist as
// plist writes it.
func parsePlist(s string) (args []string, log string) {
	str := func(v string) (string, string, bool) {
		v = strings.TrimSpace(v)
		rest, ok := strings.CutPrefix(v, "<string>")
		if !ok {
			return "", v, false
		}
		val, rest, ok := strings.Cut(rest, "</string>")
		return html.UnescapeString(val), rest, ok
	}
	if _, rest, ok := strings.Cut(s, "<key>ProgramArguments</key>"); ok {
		if _, rest, ok = strings.Cut(rest, "<array>"); ok {
			body, _, _ := strings.Cut(rest, "</array>")
			for {
				a, more, ok := str(body)
				if !ok {
					break
				}
				args, body = append(args, a), more
			}
		}
	}
	if _, rest, ok := strings.Cut(s, "<key>StandardOutPath</key>"); ok {
		log, _, _ = str(rest)
	}
	return args, log
}
