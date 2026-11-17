package migrate

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/xiongnemo/conch/internal/paths"
)

// home is a temporary home with Windows' old places in it, never the
// real one: APPDATA and LOCALAPPDATA are given to the Env, not read.
type home struct {
	t              *testing.T
	env            paths.Env
	roaming, local string // %APPDATA%\conch and %LOCALAPPDATA%\conch
	config, data   string
	state, cache   string
	vars           map[string]string
}

func newHome(t *testing.T, goos string) *home {
	t.Helper()
	dir := t.TempDir()
	h := &home{t: t, vars: map[string]string{
		"APPDATA": filepath.Join(dir, "AppData", "Roaming"), "LOCALAPPDATA": filepath.Join(dir, "AppData", "Local"),
	}}
	h.env = paths.Env{Home: dir, GOOS: goos, Getenv: func(k string) string { return h.vars[k] }}
	h.roaming, h.local = filepath.Join(h.vars["APPDATA"], "conch"), filepath.Join(h.vars["LOCALAPPDATA"], "conch")
	h.config, h.data = h.env.Dir(paths.Config), h.env.Dir(paths.Data)
	h.state, h.cache = h.env.Dir(paths.State), h.env.Dir(paths.Cache)
	return h
}

func (h *home) write(path, content string) {
	h.t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		h.t.Fatal(err)
	}
}

func (h *home) read(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return "<missing>"
	}
	return string(data)
}

// tree is every file under the home, with its content.
func (h *home) tree() map[string]string {
	files := map[string]string{}
	filepath.WalkDir(h.env.Home, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			files[p] = h.read(p)
		}
		return nil
	})
	return files
}

func (h *home) run(o Options) (string, error) {
	h.t.Helper()
	var out bytes.Buffer
	o.Env, o.Out = h.env, &out
	err := Run(o)
	return out.String(), err
}

// What a Windows user of an earlier version has.
func (h *home) legacy() {
	h.write(filepath.Join(h.roaming, "profile.yaml"), "routes: { default: DIRECT }\n")
	h.write(filepath.Join(h.roaming, "managed.yaml"), "nodes: []\n")
	h.write(filepath.Join(h.roaming, ".env"), "CONCH_PASSWORD=old\nCONCH_TLS_CERT="+filepath.Join(h.roaming, "cert.pem")+"\n")
	h.write(filepath.Join(h.roaming, "cert.pem"), "certificate")
	h.write(filepath.Join(h.local, "state.json"), `{"backend":"xray"}`)
	h.write(filepath.Join(h.local, "pairings.json"), `[]`)
	h.write(filepath.Join(h.local, "daemon.log"), "log\n")
	h.write(filepath.Join(h.local, "kernels", "mihomo", "current"), "v1\n")
	h.write(filepath.Join(h.local, "kernels", "mihomo", "v1", "mihomo.exe"), "kernel v1")
	h.write(filepath.Join(h.local, "home", "xray", "geosite.dat"), "geosite")
	h.write(filepath.Join(h.local, "subscriptions", "a.body"), "sub")
	h.write(filepath.Join(h.local, "run", "mihomo.sock"), "")
	rec, _ := json.Marshal(map[string]string{"listen": "127.0.0.1:9277", "env": filepath.Join(h.roaming, ".env")})
	h.write(filepath.Join(h.local, "api.json"), string(rec))
}

func TestDryRunTouchesNothing(t *testing.T) {
	h := newHome(t, "windows")
	h.legacy()
	before := h.tree()
	out, err := h.run(Options{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if after := h.tree(); !maps.Equal(before, after) {
		t.Errorf("a dry run changed files")
	}
	for _, want := range []string{
		"将要移动 " + filepath.Join(h.roaming, "profile.yaml") + " → " + filepath.Join(h.config, "profile.yaml"),
		"将要移动 " + filepath.Join(h.local, "kernels") + " → " + filepath.Join(h.cache, "kernels"),
		"将要删除 " + filepath.Join(h.local, "run"),
		"将要改写 " + filepath.Join(h.local, "api.json"),
		"预演",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("plan lacks %q:\n%s", want, out)
		}
	}
}

// Everything goes to its kind's directory, the old directories go, their
// parents stay, and a second run finds nothing to do.
func TestMoveAndSecondRun(t *testing.T) {
	h := newHome(t, "windows")
	h.legacy()
	out, err := h.run(Options{})
	t.Log(out)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for path, want := range map[string]string{
		filepath.Join(h.config, "profile.yaml"):                         "routes: { default: DIRECT }\n",
		filepath.Join(h.config, "managed.yaml"):                         "nodes: []\n",
		filepath.Join(h.config, "cert.pem"):                             "certificate",
		filepath.Join(h.state, "state.json"):                            `{"backend":"xray"}`,
		filepath.Join(h.state, "daemon.log"):                            "log\n",
		filepath.Join(h.data, "pairings.json"):                          `[]`,
		filepath.Join(h.cache, "kernels", "mihomo", "v1", "mihomo.exe"): "kernel v1",
		filepath.Join(h.cache, "home", "xray", "geosite.dat"):           "geosite",
		filepath.Join(h.cache, "subscriptions", "a.body"):               "sub",
	} {
		if got := h.read(path); got != want {
			t.Errorf("%s = %q, want %q", path, got, want)
		}
	}
	for _, gone := range []string{h.roaming, h.local, filepath.Join(h.state, "run")} {
		if _, err := os.Stat(gone); err == nil {
			t.Errorf("%s is still there", gone)
		}
	}
	for _, kept := range []string{h.vars["APPDATA"], h.vars["LOCALAPPDATA"]} {
		if _, err := os.Stat(kept); err != nil {
			t.Errorf("a parent of conch's directory went: %s", kept)
		}
	}
	if !strings.Contains(out, "已删除空的旧目录 "+h.roaming) {
		t.Errorf("cleanup not reported:\n%s", out)
	}
	if fi, err := os.Stat(h.config); err == nil && runtime.GOOS != "windows" && fi.Mode().Perm() != 0o700 {
		t.Errorf("new configuration directory mode %v", fi.Mode().Perm())
	}

	again, err := h.run(Options{})
	if err != nil || !strings.Contains(again, "没有需要迁移的文件") {
		t.Errorf("second run: %v\n%s", err, again)
	}
}

// Into a directory that is there already, files are merged one by one:
// the same content leaves one copy, different content both and an error.
func TestMergeSameAndConflict(t *testing.T) {
	h := newHome(t, "windows")
	h.write(filepath.Join(h.local, "kernels", "mihomo", "v1", "mihomo.exe"), "kernel v1")
	h.write(filepath.Join(h.local, "kernels", "mihomo", "v2", "mihomo.exe"), "kernel v2")
	h.write(filepath.Join(h.local, "kernels", "mihomo", "current"), "v1\n")
	h.write(filepath.Join(h.cache, "kernels", "mihomo", "v2", "mihomo.exe"), "kernel v2")
	h.write(filepath.Join(h.cache, "kernels", "mihomo", "current"), "v2\n")
	h.write(filepath.Join(h.local, "state.json"), "old state")
	h.write(filepath.Join(h.state, "state.json"), "new state")

	out, err := h.run(Options{})
	if !errors.Is(err, ErrConflicts) {
		t.Fatalf("err = %v, want conflicts\n%s", err, out)
	}
	newK, oldK := filepath.Join(h.cache, "kernels", "mihomo"), filepath.Join(h.local, "kernels", "mihomo")
	if h.read(filepath.Join(newK, "v1", "mihomo.exe")) != "kernel v1" {
		t.Error("v1 not merged in")
	}
	if _, err := os.Stat(filepath.Join(oldK, "v2")); err == nil {
		t.Error("the old copy of identical v2 was kept")
	}
	for path, want := range map[string]string{
		filepath.Join(oldK, "current"):       "v1\n",
		filepath.Join(newK, "current"):       "v2\n",
		filepath.Join(h.local, "state.json"): "old state",
		filepath.Join(h.state, "state.json"): "new state",
	} {
		if got := h.read(path); got != want {
			t.Errorf("conflict: %s = %q, both copies must stay", path, got)
		}
	}
	if !strings.Contains(out, "冲突："+filepath.Join(h.local, "state.json")) || !strings.Contains(out, "内容相同") {
		t.Errorf("output:\n%s", out)
	}
	if _, err := os.Stat(h.local); err != nil {
		t.Error("an old directory with a conflict in it was removed")
	}
}

// Across volumes a file is copied, checked and removed, keeping its mode
// and modification time.
func TestMoveAcrossVolumes(t *testing.T) {
	h := newHome(t, "windows")
	old := filepath.Join(h.local, "kernels", "mihomo", "v1", "mihomo.exe")
	h.write(old, "kernel v1")
	os.Chmod(old, 0o755)
	mtime := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	os.Chtimes(old, mtime, mtime)
	renames := 0
	out, err := h.run(Options{rename: func(from, to string) error {
		renames++
		return &os.LinkError{Op: "rename", Old: from, New: to, Err: syscall.EXDEV}
	}})
	if err != nil || renames == 0 {
		t.Fatalf("%v, %d renames\n%s", err, renames, out)
	}
	moved := filepath.Join(h.cache, "kernels", "mihomo", "v1", "mihomo.exe")
	fi, err := os.Stat(moved)
	if err != nil || h.read(moved) != "kernel v1" || !fi.ModTime().Equal(mtime) {
		t.Fatalf("copy: %v %q %v", err, h.read(moved), fi)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o755 {
		t.Errorf("mode %v, want 0755", fi.Mode().Perm())
	}
	if _, err := os.Stat(old); err == nil {
		t.Error("the source was not removed")
	}
	if !strings.Contains(out, "复制并校验") {
		t.Errorf("output:\n%s", out)
	}
}

// Paths into the old places are pointed at the new ones: in api.json, in
// .env, and in what the OS starts; the profile's are pointed out.
func TestReferencesRewritten(t *testing.T) {
	h := newHome(t, "windows")
	h.legacy()
	h.write(filepath.Join(h.roaming, "profile.yaml"), "nodes:\n  - { name: a, type: http, server: x, port: 1, certificate: "+filepath.Join(h.roaming, "client.pem")+" }\n")
	var told []string
	reg := Registration{Name: "自动启动", Rewrite: func(moved func(string) string, dry bool) (string, error) {
		old := filepath.Join(h.roaming, "profile.yaml")
		told = append(told, moved(old))
		if moved(old) == old {
			return "", nil
		}
		return "--profile " + old + " → " + moved(old), nil
	}}
	out, err := h.run(Options{Registrations: []Registration{reg}})
	t.Log(out)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	var rec map[string]string
	json.Unmarshal([]byte(h.read(filepath.Join(h.state, "api.json"))), &rec)
	if rec["env"] != filepath.Join(h.config, ".env") || rec["listen"] != "127.0.0.1:9277" {
		t.Errorf("api.json = %v", rec)
	}
	if env := h.read(filepath.Join(h.config, ".env")); env != "CONCH_PASSWORD=old\nCONCH_TLS_CERT="+filepath.Join(h.config, "cert.pem")+"\n" {
		t.Errorf(".env = %q", env)
	}
	if len(told) != 1 || told[0] != filepath.Join(h.config, "profile.yaml") || !strings.Contains(out, "已改写自动启动") {
		t.Errorf("registration told %q\n%s", told, out)
	}
	if !strings.Contains(out, "请修改："+filepath.Join(h.config, "profile.yaml")+" 第 2 行") {
		t.Errorf("the profile's old path not pointed out:\n%s", out)
	}
	if strings.Contains(h.read(filepath.Join(h.config, "profile.yaml")), h.config) {
		t.Error("the user's profile was rewritten")
	}
}

// The .env an earlier version wrote where conch ran goes to the
// configuration directory: from the current directory, or --from.
func TestEnvFromWorkingDirectory(t *testing.T) {
	h := newHome(t, "linux")
	cwd := t.TempDir()
	h.write(filepath.Join(cwd, ".env"), "CONCH_PASSWORD=cwd\n")
	out, err := h.run(Options{From: cwd, FromCwd: true, DryRun: true})
	if err != nil || !strings.Contains(out, "在当前目录找到了旧版本写的 .env："+filepath.Join(cwd, ".env")) {
		t.Fatalf("%v\n%s", err, out)
	}
	if out, err = h.run(Options{From: filepath.Join(cwd, ".env")}); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if got := h.read(filepath.Join(h.config, ".env")); got != "CONCH_PASSWORD=cwd\n" {
		t.Errorf("config .env = %q\n%s", got, out)
	}
	if _, err := os.Stat(cwd); err != nil {
		t.Error("the working directory itself was removed")
	}
	out, err = h.run(Options{From: cwd, FromCwd: true})
	if err != nil || !strings.Contains(out, "里没有旧版本写的 .env") || !strings.Contains(out, "没有需要迁移的文件") {
		t.Errorf("second run: %v\n%s", err, out)
	}
}

// On Linux the data directory stays where it was; only what is not data
// leaves it.
func TestLinuxDataDirectoryStays(t *testing.T) {
	h := newHome(t, "linux")
	h.write(filepath.Join(h.data, "pairings.json"), "[]")
	h.write(filepath.Join(h.data, "state.json"), "{}")
	h.write(filepath.Join(h.data, "kernels", "xray", "current"), "v\n")
	out, err := h.run(Options{})
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if h.read(filepath.Join(h.data, "pairings.json")) != "[]" || h.read(filepath.Join(h.state, "state.json")) != "{}" ||
		h.read(filepath.Join(h.cache, "kernels", "xray", "current")) != "v\n" {
		t.Errorf("after migrating:\n%s", out)
	}
	if strings.Contains(out, "pairings.json →") || strings.Contains(out, "已删除空的旧目录 "+h.data) {
		t.Errorf("the data directory was disturbed:\n%s", out)
	}
}

// With CONCH_DATA_DIR set, nothing but configuration is migrated.
func TestOverrideLeftAlone(t *testing.T) {
	h := newHome(t, "windows")
	h.legacy()
	h.vars["CONCH_DATA_DIR"] = t.TempDir()
	out, err := h.run(Options{})
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if h.read(filepath.Join(h.local, "state.json")) == "<missing>" || !strings.Contains(out, "CONCH_DATA_DIR 设置的") {
		t.Errorf("CONCH_DATA_DIR not respected:\n%s", out)
	}
	if h.read(filepath.Join(h.config, "profile.yaml")) == "<missing>" {
		t.Error("configuration not migrated")
	}
}

func TestPending(t *testing.T) {
	h := newHome(t, "darwin")
	if n := Pending(h.env); n != 0 {
		t.Errorf("empty home: %d pending", n)
	}
	h.write(filepath.Join(h.env.Home, "Library", "Logs", "conch", "daemon.log"), "log")
	if n := Pending(h.env); n != 1 {
		t.Errorf("an old log: %d pending", n)
	}
}
