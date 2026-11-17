package service

import (
	"slices"
	"testing"
)

// What autostart registered reads back as it was written, however the
// paths are spelled: `conch migrate` rewrites it from what it reads.
func TestReadBackRegistered(t *testing.T) {
	for _, a := range []Autostart{
		{Bin: "/usr/bin/conch", Profile: "/home/a/.config/conch/profile.yaml", LogFile: "/home/a/.local/state/conch/daemon.log"},
		{Bin: "/opt/my conch/conch", Profile: `/home/a/50% "x" $y` + "`z`" + `\w/profile.yaml`, LogFile: "/Users/a & b/<log>"},
	} {
		want := a.Args()
		if got := parseSystemdExec(mustKey(t, SystemdUserUnit(a), "ExecStart")); !slices.Equal(got, want) {
			t.Errorf("systemd unit reads back %q, want %q", got, want)
		}
		if got := parseDesktopExec(mustKey(t, DesktopEntry(a), "Exec")); !slices.Equal(got, want) {
			t.Errorf("desktop entry reads back %q, want %q", got, want)
		}
		args, log := parsePlist(LaunchdUserPlist(a))
		if !slices.Equal(args, want) || log != a.LogFile {
			t.Errorf("plist reads back %q, %q", args, log)
		}
		r := Registered{Args: want}
		if r.Profile() != a.Profile {
			t.Errorf("profile = %q", r.Profile())
		}
		if b := r.Autostart(Autostart{Dir: "d"}, "/new/profile.yaml", "/new/daemon.log"); b.Bin != a.Bin || b.Profile != "/new/profile.yaml" || b.Dir != "d" {
			t.Errorf("rewritten as %+v", b)
		}
	}
}

func mustKey(t *testing.T, content, key string) string {
	t.Helper()
	v, ok := keyLine(content, key)
	if !ok {
		t.Fatalf("no %s= in\n%s", key, content)
	}
	return v
}
