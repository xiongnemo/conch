package paths

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// testEnv is an Env with a home of its own and only the variables given,
// which records what it is told about old places.
func testEnv(t *testing.T, goos string, vars map[string]string) (Env, *[]string) {
	t.Helper()
	var told []string
	home := t.TempDir()
	return Env{Home: home, GOOS: goos, Getenv: func(k string) string { return vars[k] },
		Notify: func(what, old, new string) { told = append(told, what+" "+old+" -> "+new) }}, &told
}

func write(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(path), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The XDG variables count only when absolute, on every OS; the defaults
// are under the home, Windows and macOS included.
func TestDirs(t *testing.T) {
	abs := t.TempDir()
	defaults := func(home string) map[Kind]string {
		return map[Kind]string{
			Config: filepath.Join(home, ".config", "conch"),
			Data:   filepath.Join(home, ".local", "share", "conch"),
			State:  filepath.Join(home, ".local", "state", "conch"),
		}
	}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			unset, _ := testEnv(t, goos, nil)
			for k, w := range defaults(unset.Home) {
				if got := unset.Dir(k); got != w {
					t.Errorf("unset: %s = %s, want %s", k, got, w)
				}
			}
			if got, want := unset.RunDir(), filepath.Join(defaults(unset.Home)[State], "run"); got != want {
				t.Errorf("unset: run = %s, want %s", got, want)
			}

			set, _ := testEnv(t, goos, map[string]string{
				"XDG_CONFIG_HOME": filepath.Join(abs, "c"), "XDG_DATA_HOME": filepath.Join(abs, "d"),
				"XDG_STATE_HOME": filepath.Join(abs, "s"), "XDG_CACHE_HOME": filepath.Join(abs, "k"),
				"XDG_RUNTIME_DIR": filepath.Join(abs, "r"),
			})
			for k, sub := range map[Kind]string{Config: "c", Data: "d", State: "s"} {
				if got, w := set.Dir(k), filepath.Join(abs, sub, "conch"); got != w {
					t.Errorf("set: %s = %s, want %s", k, got, w)
				}
			}
			if got, w := set.RunDir(), filepath.Join(abs, "r", "conch"); got != w {
				t.Errorf("set: run = %s, want %s", got, w)
			}
			// Nothing conch keeps is in a cache directory: people clear
			// those, and conch could not start without the network then.
			for _, it := range Items() {
				for _, cache := range []string{filepath.Join(abs, "k"), filepath.Join(set.Home, ".cache")} {
					if p := set.New(it); strings.HasPrefix(p, cache) {
						t.Errorf("%s goes to the cache directory: %s", it.what, p)
					}
				}
			}

			relative, _ := testEnv(t, goos, map[string]string{
				"XDG_CONFIG_HOME": "rel", "XDG_DATA_HOME": "rel", "XDG_STATE_HOME": "rel", "XDG_CACHE_HOME": "rel", "XDG_RUNTIME_DIR": "rel",
			})
			for k, w := range defaults(relative.Home) {
				if got := relative.Dir(k); got != w {
					t.Errorf("relative: %s = %s, want the default %s", k, got, w)
				}
			}
			if got := relative.RunDir(); got != filepath.Join(relative.Home, ".local", "state", "conch", "run") {
				t.Errorf("relative XDG_RUNTIME_DIR used: %s", got)
			}
		})
	}
}

// CONCH_CONFIG_DIR and CONCH_DATA_DIR win, everything but configuration
// in the second, and nothing is looked for at old places then.
func TestOverrides(t *testing.T) {
	cfg, data := t.TempDir(), t.TempDir()
	e, told := testEnv(t, "windows", map[string]string{"CONCH_CONFIG_DIR": cfg, "CONCH_DATA_DIR": data, "APPDATA": t.TempDir(), "LOCALAPPDATA": t.TempDir()})
	write(t, filepath.Join(e.Getenv("APPDATA"), "conch", "profile.yaml"))
	write(t, filepath.Join(e.Getenv("LOCALAPPDATA"), "conch", "state.json"))
	if got := e.Profile(); got != filepath.Join(cfg, "profile.yaml") {
		t.Errorf("profile = %s", got)
	}
	for got, want := range map[string]string{
		e.StateFile(): filepath.Join(data, "state.json"), e.Kernels(): filepath.Join(data, "kernels"),
		e.Pairings(): filepath.Join(data, "pairings.json"), e.RunDir(): filepath.Join(data, "run"),
	} {
		if got != want {
			t.Errorf("got %s, want %s", got, want)
		}
	}
	if len(*told) != 0 || e.OldConfigDirs() != nil || e.OldDataDirs() != nil {
		t.Errorf("old places looked at: %q", *told)
	}
}

// Each item is found on its own: at its new place, else at an old one
// (said once), else at the new place.
func TestResolveEachItem(t *testing.T) {
	e, told := testEnv(t, "darwin", nil)
	support := filepath.Join(e.Home, "Library", "Application Support", "conch")
	write(t, filepath.Join(support, "state.json"))                       // old only
	write(t, filepath.Join(support, "certs.json"))                       // both
	write(t, filepath.Join(e.Dir(Data), "certs.json"))                   //
	write(t, filepath.Join(e.Dir(Data), "kernels", "mihomo", "current")) // new only
	write(t, filepath.Join(e.Home, "Library", "Logs", "conch", "daemon.log"))

	cases := []struct{ name, got, want string }{
		{"old only", e.StateFile(), filepath.Join(support, "state.json")},
		{"both", e.Certs(), filepath.Join(e.Dir(Data), "certs.json")},
		{"new only", e.Kernels(), filepath.Join(e.Dir(Data), "kernels")},
		{"neither", e.Pairings(), filepath.Join(e.Dir(Data), "pairings.json")},
		{"neither, a directory", e.Lists(), filepath.Join(e.Dir(Data), "lists")},
		{"the old log directory", e.DaemonLog(), filepath.Join(e.Home, "Library", "Logs", "conch", "daemon.log")},
		{"configuration was in ~/.config already", e.Profile(), filepath.Join(e.Home, ".config", "conch", "profile.yaml")},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: %s, want %s", c.name, c.got, c.want)
		}
	}
	if len(*told) != 2 {
		t.Errorf("told %q, want state.json and daemon.log", *told)
	}
	for _, it := range Items() {
		for _, old := range e.Legacy(it) {
			if e.Same(old, e.New(it)) {
				t.Errorf("%s: the new place %s is listed as old", it.what, old)
			}
		}
	}
}

// An empty directory a newer version made does not hide an old item.
func TestEmptyDirectoryDoesNotHide(t *testing.T) {
	e, _ := testEnv(t, "windows", map[string]string{"LOCALAPPDATA": filepath.Join(t.TempDir(), "Local")})
	old := filepath.Join(e.Getenv("LOCALAPPDATA"), "conch", "kernels")
	write(t, filepath.Join(old, "mihomo", "current"))
	os.MkdirAll(filepath.Join(e.Dir(Data), "kernels", "mihomo"), 0o700)
	if got := e.Kernels(); got != old {
		t.Errorf("kernels = %s, want the old %s", got, old)
	}
	write(t, filepath.Join(e.Dir(Data), "kernels", "mihomo", "current"))
	if got := e.Kernels(); got != filepath.Join(e.Dir(Data), "kernels") {
		t.Errorf("kernels = %s once the new place has them", got)
	}
}

// Where released versions kept things, per OS.
func TestOldPlaces(t *testing.T) {
	roaming, local, xdgData := filepath.Join(t.TempDir(), "Roaming"), filepath.Join(t.TempDir(), "Local"), t.TempDir()

	win, _ := testEnv(t, "windows", map[string]string{"APPDATA": roaming, "LOCALAPPDATA": local})
	if got, want := win.OldConfigDirs(), []string{filepath.Join(roaming, "conch")}; !slices.Equal(got, want) {
		t.Errorf("windows config: %q, want %q", got, want)
	}
	if got := win.OldDataDirs(); len(got) == 0 || got[0] != filepath.Join(local, "conch") {
		t.Errorf("windows data: %q", got)
	}

	mac, _ := testEnv(t, "darwin", map[string]string{"XDG_CONFIG_HOME": t.TempDir()})
	if got, want := mac.OldConfigDirs(), []string{filepath.Join(mac.Home, ".config", "conch")}; !slices.Equal(got, want) {
		t.Errorf("darwin with XDG_CONFIG_HOME: %q, want %q", got, want)
	}
	if got := mac.OldDataDirs(); got[0] != filepath.Join(mac.Home, "Library", "Application Support", "conch") {
		t.Errorf("darwin data: %q", got)
	}
	if got, want := mac.OldLogDirs(), []string{filepath.Join(mac.Home, "Library", "Logs", "conch")}; !slices.Equal(got, want) {
		t.Errorf("darwin logs: %q", got)
	}

	linux, _ := testEnv(t, "linux", map[string]string{"XDG_DATA_HOME": xdgData})
	if got := linux.OldConfigDirs(); got != nil {
		t.Errorf("linux config moved nowhere, got %q", got)
	}
	if got, want := linux.OldDataDirs(), []string{filepath.Join(xdgData, "conch"), filepath.Join(linux.Home, ".local", "share", "conch")}; !slices.Equal(got, want) {
		t.Errorf("linux data: %q, want %q", got, want)
	}
	// On Linux the data directory stays: state.json leaves it, the kernels do not.
	write(t, filepath.Join(xdgData, "conch", "state.json"))
	write(t, filepath.Join(xdgData, "conch", "kernels", "xray", "current"))
	if got := linux.StateFile(); got != filepath.Join(xdgData, "conch", "state.json") {
		t.Errorf("state.json = %s", got)
	}
	if got := linux.Kernels(); got != filepath.Join(xdgData, "conch", "kernels") {
		t.Errorf("kernels = %s", got)
	}
	if got := linux.Legacy(kernelsItem); slices.Contains(got, filepath.Join(xdgData, "conch", "kernels")) {
		t.Errorf("the new place of the kernels is an old one too: %q", got)
	}
	if got, want := linux.OldRunDirs(), []string{filepath.Join(xdgData, "conch", "run"), filepath.Join(linux.Home, ".local", "share", "conch", "run")}; !slices.Equal(got, want) {
		t.Errorf("linux old run directories: %q", got)
	}
}

// ForUser looks where the user's own conch would, without the
// environment of the one running it.
func TestForUser(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	e := ForUser(home)
	if got := e.Dir(Config); got != filepath.Join(home, ".config", "conch") {
		t.Errorf("config = %s", got)
	}
	if got := e.Kernels(); got != filepath.Join(home, ".local", "share", "conch", "kernels") {
		t.Errorf("kernels = %s", got)
	}
}
