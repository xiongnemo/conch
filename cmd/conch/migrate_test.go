package main

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xiongnemo/conch/internal/migrate"
	"github.com/xiongnemo/conch/internal/paths"
)

// conch migrate, in a home of the test's own: what an earlier version left
// is read where it is, then moved; a second run has nothing to do.
func TestMigrateCommand(t *testing.T) {
	home := t.TempDir()
	useHome(t, home)
	// Nothing answers here: no daemon of the machine's own is asked.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Setenv("CONCH_LISTEN", ln.Addr().String())
	ln.Close()
	defer func(old func() []migrate.Registration) { registrations = old }(registrations)
	registrations = func() []migrate.Registration { return nil }

	oldState := filepath.Join(home, ".local", "share", "conch", "state.json") // an old place on every OS
	os.MkdirAll(filepath.Dir(oldState), 0o700)
	os.WriteFile(oldState, []byte(`{"backend":"sing-box"}`), 0o600)
	cwd := t.TempDir()
	os.WriteFile(filepath.Join(cwd, ".env"), []byte("CONCH_PASSWORD=from-cwd\n"), 0o600)
	t.Chdir(cwd)

	if got := paths.StateFile(); got != oldState {
		t.Fatalf("state.json found at %s, want the old place", got)
	}
	run := func(args ...string) (string, error) {
		cmd := newMigrateCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs(args)
		err := cmd.Execute()
		return out.String(), err
	}
	out, err := run("--dry-run")
	if err != nil || !strings.Contains(out, "将要移动 "+oldState) || !strings.Contains(out, "在当前目录找到了旧版本写的 .env") {
		t.Fatalf("dry run: %v\n%s", err, out)
	}
	if _, err := os.Stat(oldState); err != nil {
		t.Fatal("the dry run moved state.json")
	}
	if out, err = run(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	newState := filepath.Join(home, ".local", "state", "conch", "state.json")
	if got := paths.StateFile(); got != newState {
		t.Errorf("state.json found at %s, want %s\n%s", got, newState, out)
	}
	if env, _ := os.ReadFile(filepath.Join(home, ".config", "conch", ".env")); string(env) != "CONCH_PASSWORD=from-cwd\n" {
		t.Errorf("config .env = %q", env)
	}
	if out, err = run(); err != nil || !strings.Contains(out, "没有需要迁移的文件") {
		t.Errorf("second run: %v\n%s", err, out)
	}
}
