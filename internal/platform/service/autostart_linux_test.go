package service

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testAutostart(t *testing.T, systemd bool) (Autostart, *[]string) {
	config := t.TempDir()
	var calls []string
	run := func(name string, args ...string) (string, error) {
		call := name + " " + strings.Join(args, " ")
		calls = append(calls, call)
		switch {
		case call == "systemctl --user show-environment" && !systemd:
			return "", errors.New("Failed to connect to bus")
		case strings.HasSuffix(call, "is-active conch.service"):
			return "active", nil
		}
		return "", nil
	}
	return Autostart{Bin: "/usr/bin/conch", Profile: filepath.Join(config, "conch", "profile.yaml"),
		Dir: filepath.Join(config, "systemd", "user"), AutostartDir: filepath.Join(config, "autostart"), Run: run}, &calls
}

// With a systemd user session: a user unit, enabled and started; off
// stops and removes it.
func TestAutostartSystemdUser(t *testing.T) {
	a, calls := testAutostart(t, true)
	if err := EnableAutostart(a); err != nil {
		t.Fatal(err)
	}
	unit, _ := os.ReadFile(filepath.Join(a.Dir, "conch.service"))
	if !strings.Contains(string(unit), "ExecStart=/usr/bin/conch daemon --autostart --chdir "+filepath.Dir(a.Profile)) || !strings.Contains(string(unit), "WantedBy=default.target") {
		t.Errorf("unit:\n%s", unit)
	}
	if want := "systemctl --user enable --now conch.service"; !strings.Contains(strings.Join(*calls, "\n"), want) {
		t.Errorf("calls = %q, want %q", *calls, want)
	}
	if s, err := AutostartStatus(a); err != nil || !strings.Contains(s, "active") {
		t.Errorf("status = %q, %v", s, err)
	}
	if err := DisableAutostart(a); err != nil {
		t.Fatal(err)
	}
	if exists(filepath.Join(a.Dir, "conch.service")) || !strings.Contains(strings.Join(*calls, "\n"), "systemctl --user disable --now conch.service") {
		t.Errorf("not removed: %q", *calls)
	}
	if err := DisableAutostart(a); !errors.Is(err, ErrAutostartOff) {
		t.Errorf("off again: %v", err)
	}
}

// Without one: an autostart entry of the desktop.
func TestAutostartDesktopEntry(t *testing.T) {
	a, _ := testAutostart(t, false)
	if err := EnableAutostart(a); err != nil {
		t.Fatal(err)
	}
	if exists(filepath.Join(a.Dir, "conch.service")) || !exists(filepath.Join(a.AutostartDir, "conch.desktop")) {
		t.Fatal("want only conch.desktop")
	}
	if s, err := AutostartStatus(a); err != nil || !strings.Contains(s, "conch.desktop") {
		t.Errorf("status = %q, %v", s, err)
	}
	if err := DisableAutostart(a); err != nil || exists(filepath.Join(a.AutostartDir, "conch.desktop")) {
		t.Errorf("off: %v", err)
	}
}
