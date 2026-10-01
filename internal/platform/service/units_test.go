package service

import (
	"encoding/xml"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func testLayout() Layout {
	return Layout{Bin: "/usr/local/bin/nautilus", ConfigDir: "/etc/nautilus", DataDir: "/var/lib/nautilus", Log: "/Library/Logs/nautilus.log"}
}

func TestSystemdUnits(t *testing.T) {
	unit := SystemdUnit(testLayout())
	for _, want := range []string{
		"ExecStart=/usr/local/bin/nautilus daemon --service --config-dir /etc/nautilus --data-dir /var/lib/nautilus",
		"User=nautilus", "AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW",
		"ReadWritePaths=/etc/nautilus /var/lib/nautilus", "WantedBy=multi-user.target",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit lacks %q:\n%s", want, unit)
		}
	}
	spaced := SystemdAgentUnit(Layout{Bin: "/opt/my apps/nautilus"})
	if !strings.Contains(spaced, `ExecStart="/opt/my apps/nautilus" agent`) {
		t.Errorf("paths with spaces must be quoted:\n%s", spaced)
	}
}

// systemd itself checks the units, where it is available.
func TestSystemdAnalyzeVerify(t *testing.T) {
	analyze, err := exec.LookPath("systemd-analyze")
	if err != nil {
		t.Skip("no systemd-analyze")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "nautilus")
	os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755)
	l := Layout{Bin: bin, ConfigDir: dir, DataDir: dir}
	for name, unit := range map[string]string{"nautilus.service": SystemdUnit(l), "nautilus-agent.service": SystemdAgentUnit(l)} {
		path := filepath.Join(dir, name)
		os.WriteFile(path, []byte(unit), 0o644)
		out, err := exec.Command(analyze, "verify", path).CombinedOutput()
		// The nautilus user does not exist here; everything else must pass.
		var problems []string
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if line != "" && !strings.Contains(line, "nautilus") || strings.Contains(line, "Unknown key") || strings.Contains(line, "Invalid") {
				problems = append(problems, line)
			}
		}
		if err != nil && len(problems) > 0 {
			t.Errorf("%s: %v\n%s", name, err, out)
		}
	}
}

func TestLaunchdPlists(t *testing.T) {
	l := testLayout()
	l.ConfigDir = "/Library/Application Support/nautilus"
	for _, p := range []string{LaunchdDaemonPlist(l), LaunchdAgentPlist(l)} {
		d := xml.NewDecoder(strings.NewReader(p))
		d.Strict = true
		for {
			if _, err := d.Token(); err == io.EOF {
				break
			} else if err != nil {
				t.Fatalf("plist is not XML: %v\n%s", err, p)
			}
		}
	}
	if p := LaunchdDaemonPlist(l); !strings.Contains(p, "<string>/Library/Application Support/nautilus</string>") || !strings.Contains(p, "<string>--service</string>") {
		t.Errorf("daemon plist:\n%s", p)
	}
}
