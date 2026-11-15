//go:build !windows

package service

import (
	"slices"
	"strings"
	"testing"
)

func TestAutostartArgs(t *testing.T) {
	a := Autostart{Bin: "/usr/bin/conch", Profile: "/home/a/.config/conch/profile.yaml"}
	want := []string{"/usr/bin/conch", "daemon", "--autostart", "--chdir", "/home/a/.config/conch", "--profile", "/home/a/.config/conch/profile.yaml"}
	if got := a.Args(); !slices.Equal(got, want) {
		t.Errorf("args = %q", got)
	}
}

func TestDesktopEntry(t *testing.T) {
	a := Autostart{Bin: "/opt/my conch/conch", Profile: `/home/a/50% "x"/profile.yaml`}
	e := DesktopEntry(a)
	want := `Exec="/opt/my conch/conch" daemon --autostart --chdir "/home/a/50%% \\"x\\"" --profile "/home/a/50%% \\"x\\"/profile.yaml"`
	if !strings.Contains(e, want+"\n") {
		t.Errorf("entry:\n%s\nwant line:\n%s", e, want)
	}
}
