package service

import (
	"fmt"
	"html"
	"strings"
)

// The service files for each OS. They are plain text so tests can read
// them and `systemd-analyze verify` can check them on any Linux machine.

// Capabilities the daemon passes on to the kernel for TUN.
const systemdCaps = "CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW"

// SystemdUnit runs the daemon as the unprivileged user nautilus, with
// just the capabilities TUN needs.
func SystemdUnit(l Layout) string {
	return fmt.Sprintf(`# Installed by nautilus service install.
[Unit]
Description=Nautilus proxy daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nautilus
Group=nautilus
ExecStart=%s daemon --service --config-dir %s --data-dir %s
WorkingDirectory=%s
AmbientCapabilities=%s
CapabilityBoundingSet=%s
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=%s %s
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
`, systemdQuote(l.Bin), systemdQuote(l.ConfigDir), systemdQuote(l.DataDir), l.ConfigDir, systemdCaps, systemdCaps, l.ConfigDir, l.DataDir)
}

// SystemdAgentUnit runs the agent in every user's session.
func SystemdAgentUnit(l Layout) string {
	return fmt.Sprintf(`# Installed by nautilus service install.
[Unit]
Description=Nautilus agent: system proxy for this session

[Service]
Type=simple
ExecStart=%s agent
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
`, systemdQuote(l.Bin))
}

func systemdQuote(s string) string {
	if !strings.ContainsAny(s, " \t\"\\") {
		return s
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// Launchd labels.
const (
	LaunchdDaemon = "io.nautilus.daemon"
	LaunchdAgent  = "io.nautilus.agent"
)

// LaunchdDaemonPlist runs the daemon as root, which TUN needs on macOS.
func LaunchdDaemonPlist(l Layout) string {
	return plist(LaunchdDaemon, []string{l.Bin, "daemon", "--service", "--config-dir", l.ConfigDir, "--data-dir", l.DataDir}, l.ConfigDir, l.Log)
}

// LaunchdAgentPlist runs the agent in every user's session.
func LaunchdAgentPlist(l Layout) string {
	return plist(LaunchdAgent, []string{l.Bin, "agent"}, "", "")
}

func plist(label string, args []string, dir, log string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
`)
	fmt.Fprintf(&b, "\t<key>Label</key>\n\t<string>%s</string>\n", html.EscapeString(label))
	b.WriteString("\t<key>ProgramArguments</key>\n\t<array>\n")
	for _, a := range args {
		fmt.Fprintf(&b, "\t\t<string>%s</string>\n", html.EscapeString(a))
	}
	b.WriteString("\t</array>\n")
	if dir != "" {
		fmt.Fprintf(&b, "\t<key>WorkingDirectory</key>\n\t<string>%s</string>\n", html.EscapeString(dir))
	}
	if log != "" {
		fmt.Fprintf(&b, "\t<key>StandardOutPath</key>\n\t<string>%s</string>\n\t<key>StandardErrorPath</key>\n\t<string>%s</string>\n", html.EscapeString(log), html.EscapeString(log))
	}
	b.WriteString("\t<key>RunAtLoad</key>\n\t<true/>\n\t<key>KeepAlive</key>\n\t<true/>\n</dict>\n</plist>\n")
	return b.String()
}
