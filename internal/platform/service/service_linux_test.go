package service

import (
	"bytes"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/xiongnemo/conch/internal/auth"
	"github.com/xiongnemo/conch/internal/paths"
)

// Installing writes everything under a fake root and records the
// commands instead of running them.
func TestInstallSystemd(t *testing.T) {
	root, home := t.TempDir(), t.TempDir()
	userConfig, userData := paths.UserDirs(home)
	os.MkdirAll(userConfig, 0o700)
	profile := filepath.Join(userConfig, "profile.yaml")
	os.WriteFile(profile, []byte("routes: { default: DIRECT }\n"), 0o644)
	os.WriteFile(filepath.Join(userConfig, ".env"), []byte("CONCH_PASSWORD=users-own\n"), 0o600)
	kernel := filepath.Join(userData, "kernels", "mihomo", "v1.19.32", "mihomo")
	os.MkdirAll(filepath.Dir(kernel), 0o755)
	os.WriteFile(kernel, []byte("kernel"), 0o755)
	exe := filepath.Join(t.TempDir(), "conch")
	os.WriteFile(exe, []byte("conch binary"), 0o755)

	defer func(old func(string) (*user.User, error)) { lookupUser = old }(lookupUser)
	lookupUser = func(name string) (*user.User, error) { return nil, user.UnknownUserError(name) }
	var calls []string
	run := func(name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		switch strings.Join(args, " ") {
		case "is-active conch.service":
			return "active", nil
		case "is-enabled conch.service":
			return "enabled", nil
		}
		return "", nil
	}
	var log bytes.Buffer
	l := SystemLayout()
	o := Options{Layout: l, User: &User{Name: "alice", UID: "1000", Home: home, ConfigDir: userConfig, DataDir: userData},
		Run: run, Log: &log, Profile: profile, Exe: exe, Root: root}
	if err := Install(o); err != nil {
		t.Fatal(err)
	}

	read := func(p string) string { data, _ := os.ReadFile(filepath.Join(root, p)); return string(data) }
	if read(l.Bin) != "conch binary" || read("/etc/conch/profile.yaml") != "routes: { default: DIRECT }\n" ||
		read("/var/lib/conch/kernels/mihomo/v1.19.32/mihomo") != "kernel" {
		t.Error("binary, profile or kernel not carried over")
	}
	// The user's password is kept, so their CLI and agent keep working.
	if pw := auth.PasswordIn(filepath.Join(root, "/etc/conch/.env")); pw != "users-own" {
		t.Errorf("service password = %q", pw)
	}
	if read(unitPath) != SystemdUnit(l) || read(agentUnitPath) != SystemdAgentUnit(l) {
		t.Error("units not written")
	}
	for _, want := range []string{
		"useradd --system --user-group --home-dir /var/lib/conch --no-create-home --shell /usr/sbin/nologin conch",
		"chown -R conch:conch /etc/conch /var/lib/conch",
		"systemctl daemon-reload", "systemctl enable --now conch.service",
		"systemctl --global enable conch-agent.service",
		"systemctl --user --machine alice@ start conch-agent.service",
	} {
		if !slices.Contains(calls, want) {
			t.Errorf("missing %q in %q", want, calls)
		}
	}

	if s, err := Status(o); err != nil || s != "conch.service：active，开机启动：enabled" {
		t.Errorf("status = %q, %v", s, err)
	}
	calls = nil
	if err := Uninstall(o); err != nil {
		t.Fatal(err)
	}
	if read(unitPath) != "" || read(agentUnitPath) != "" || read("/etc/conch/profile.yaml") == "" {
		t.Error("uninstall must remove the units and keep the configuration")
	}
	if !slices.Contains(calls, "systemctl disable --now conch.service") {
		t.Errorf("uninstall calls %q", calls)
	}
	if err := Uninstall(o); err != ErrNotInstalled {
		t.Errorf("second uninstall: %v", err)
	}
}

// Without a password anywhere, one is made for both the service and the user.
func TestInstallMakesPassword(t *testing.T) {
	root, home := t.TempDir(), t.TempDir()
	userConfig, userData := paths.UserDirs(home)
	defer func(old func(string) (*user.User, error)) { lookupUser = old }(lookupUser)
	lookupUser = func(string) (*user.User, error) { return &user.User{}, nil }
	exe := filepath.Join(t.TempDir(), "conch")
	os.WriteFile(exe, []byte("x"), 0o755)
	o := Options{Layout: SystemLayout(), User: &User{Name: "bob", ConfigDir: userConfig, DataDir: userData}, NoAgent: true,
		Run: func(string, ...string) (string, error) { return "", nil }, Exe: exe, Root: root}
	if err := Install(o); err != nil {
		t.Fatal(err)
	}
	service, users := auth.PasswordIn(filepath.Join(root, "/etc/conch/.env")), auth.PasswordIn(filepath.Join(userConfig, ".env"))
	if service == "" || service != users {
		t.Errorf("passwords: service %q, user %q", service, users)
	}
	if _, err := os.Stat(filepath.Join(root, agentUnitPath)); err == nil {
		t.Error("agent installed despite NoAgent")
	}
}
