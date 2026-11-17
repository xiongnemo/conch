package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestMain gives the tests a home of their own: whatever a test does not
// set itself, conch looks for in an empty temporary home, never the real
// one with its passwords and nodes.
func TestMain(m *testing.M) {
	home, err := os.MkdirTemp("", "conch-test-home-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	sandbox(home)
	code := m.Run()
	os.RemoveAll(home)
	os.Exit(code)
}

// useHome moves a test into a home of its own until it ends.
func useHome(t *testing.T, home string) {
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("APPDATA", filepath.Join(home, "AppData", "Roaming"))
	t.Setenv("LOCALAPPDATA", filepath.Join(home, "AppData", "Local"))
}

// sandbox points every variable conch finds per-user files by at home,
// and drops the ones that would point elsewhere.
func sandbox(home string) {
	for k, v := range map[string]string{
		"HOME": home, "USERPROFILE": home,
		"APPDATA": filepath.Join(home, "AppData", "Roaming"), "LOCALAPPDATA": filepath.Join(home, "AppData", "Local"),
	} {
		os.Setenv(k, v)
	}
	for _, k := range []string{"XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "XDG_RUNTIME_DIR",
		"CONCH_CONFIG_DIR", "CONCH_DATA_DIR", "CONCH_PASSWORD", "CONCH_LISTEN", "CONCH_AUTH", "CONCH_TLS_CERT", "CONCH_TLS_KEY"} {
		os.Unsetenv(k)
	}
}
