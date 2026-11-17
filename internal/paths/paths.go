// Package paths locates conch's per-user files. They follow the XDG Base
// Directory layout on every OS, Windows and macOS included:
//
//	config  $XDG_CONFIG_HOME/conch  ~/.config/conch       profile.yaml, managed.yaml, .env
//	data    $XDG_DATA_HOME/conch    ~/.local/share/conch  pairings.json, kernels, their working
//	                                                      directories, rule lists, subscriptions,
//	                                                      certs.json
//	state   $XDG_STATE_HOME/conch   ~/.local/state/conch  state.json, api.json, agent.json, logs
//
// Nothing goes in ~/.cache: what conch needs to bring the proxy up without
// network access is data, since downloading it again may need the proxy,
// and people clear their caches freely.
//
// An XDG variable only counts when it is an absolute path. CONCH_CONFIG_DIR
// and CONCH_DATA_DIR still win: the first for configuration, the second for
// everything else, all in one directory as before (the system service and
// tests use them).
//
// The places earlier versions used keep working: each item is looked up
// on its own, at its new place first, then at the old ones, and one taken
// from an old place is mentioned on stderr once per run, until
// `conch migrate` moves it.
package paths

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

const app = "conch"

// Kind is one of the XDG base directories.
type Kind int

const (
	Config Kind = iota // what the user writes, and settings conch saves for them
	Data               // what cannot be made again offline: kernels and downloads included
	State              // what a run leaves for the next: state, logs, records
)

// String names a kind in messages.
func (k Kind) String() string { return [...]string{"配置", "数据", "状态"}[k] }

// Kinds lists every kind conch keeps files of.
var Kinds = []Kind{Config, Data, State}

// Env is what locating files depends on. System is this process's; tests
// make their own.
type Env struct {
	Home   string // os.UserHomeDir: $HOME, or %USERPROFILE% on Windows
	GOOS   string
	Getenv func(string) string
	// Notify hears about an item used from an old place; nil means a line
	// on stderr, once per item and run.
	Notify func(what, old, new string)
}

// System is the Env of this process.
func System() Env {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return Env{Home: home, GOOS: runtime.GOOS, Getenv: os.Getenv}
}

// ForUser is the Env of the user whose home is home, without anything
// from the environment: for `sudo conch service install`, which sets
// things up for the user who ran sudo. On Windows, %APPDATA% and
// %LOCALAPPDATA% are their usual places in that home.
func ForUser(home string) Env {
	vars := map[string]string{}
	if runtime.GOOS == "windows" {
		vars["APPDATA"] = filepath.Join(home, "AppData", "Roaming")
		vars["LOCALAPPDATA"] = filepath.Join(home, "AppData", "Local")
	}
	return Env{Home: home, GOOS: runtime.GOOS, Getenv: func(k string) string { return vars[k] }}
}

// Override is the directory an environment variable sets for a kind, if
// any, and the variable: CONCH_CONFIG_DIR, or CONCH_DATA_DIR for the rest.
func (e Env) Override(k Kind) (dir, name string) {
	name = "CONCH_DATA_DIR"
	if k == Config {
		name = "CONCH_CONFIG_DIR"
	}
	return e.Getenv(name), name
}

var xdgHomes = [...]struct {
	name string
	def  []string
}{
	Config: {"XDG_CONFIG_HOME", []string{".config"}},
	Data:   {"XDG_DATA_HOME", []string{".local", "share"}},
	State:  {"XDG_STATE_HOME", []string{".local", "state"}},
}

// Dir is the directory for a kind of file.
func (e Env) Dir(k Kind) string {
	if d, _ := e.Override(k); d != "" {
		return d
	}
	return e.xdg(k)
}

func (e Env) xdg(k Kind) string {
	x := xdgHomes[k]
	if d := e.Getenv(x.name); filepath.IsAbs(d) {
		return filepath.Join(d, app)
	}
	return filepath.Join(append(append([]string{e.Home}, x.def...), app)...)
}

// RunDir is where the kernels' sockets and pid files go: under
// CONCH_DATA_DIR as before when it is set, else $XDG_RUNTIME_DIR/conch
// when that is absolute, else run in the state directory.
func (e Env) RunDir() string {
	if d, _ := e.Override(State); d != "" {
		return filepath.Join(d, "run")
	}
	if d := e.Getenv("XDG_RUNTIME_DIR"); filepath.IsAbs(d) {
		return filepath.Join(d, app)
	}
	return filepath.Join(e.Dir(State), "run")
}

// OldConfigDirs are where released versions kept configuration, other
// than the new place: %APPDATA%\conch (os.UserConfigDir) on Windows, and
// ~/.config/conch where XDG_CONFIG_HOME now points elsewhere. There are
// none with CONCH_CONFIG_DIR set.
func (e Env) OldConfigDirs() []string {
	if d, _ := e.Override(Config); d != "" {
		return nil
	}
	var dirs []string
	if e.GOOS == "windows" {
		if d := e.Getenv("APPDATA"); d != "" {
			dirs = append(dirs, filepath.Join(d, app))
		}
	}
	dirs = append(dirs, filepath.Join(e.Home, ".config", app))
	return e.without(dirs, e.Dir(Config))
}

// OldDataDirs are where released versions kept everything but
// configuration: %LOCALAPPDATA%\conch on Windows, ~/Library/Application
// Support/conch on macOS, $XDG_DATA_HOME/conch or ~/.local/share/conch
// elsewhere. On Linux that is the new data directory too: only state
// leaves it. There are none with CONCH_DATA_DIR set.
func (e Env) OldDataDirs() []string {
	if d, _ := e.Override(Data); d != "" {
		return nil
	}
	var dirs []string
	switch e.GOOS {
	case "windows":
		if d := e.Getenv("LOCALAPPDATA"); d != "" {
			dirs = append(dirs, filepath.Join(d, app))
		}
	case "darwin":
		dirs = append(dirs, filepath.Join(e.Home, "Library", "Application Support", app))
	}
	if d := e.Getenv("XDG_DATA_HOME"); filepath.IsAbs(d) && e.GOOS != "darwin" {
		dirs = append(dirs, filepath.Join(d, app))
	}
	dirs = append(dirs, filepath.Join(e.Home, ".local", "share", app))
	return e.without(dirs)
}

// OldLogDirs are where released versions kept logs outside the data
// directory: ~/Library/Logs/conch on macOS, for the daemon autostart runs.
func (e Env) OldLogDirs() []string {
	if d, _ := e.Override(State); d != "" || e.GOOS != "darwin" {
		return nil
	}
	return []string{filepath.Join(e.Home, "Library", "Logs", app)}
}

// OldRunDirs are the run directories of the old data directories, other
// than the new one: kernels a crashed daemon of an earlier version left
// running are found by the pid files there.
func (e Env) OldRunDirs() []string {
	var dirs []string
	for _, d := range e.OldDataDirs() {
		dirs = append(dirs, filepath.Join(d, "run"))
	}
	return e.without(dirs, e.RunDir())
}

// without drops duplicates, and the paths in drop.
func (e Env) without(paths []string, drop ...string) []string {
	var out []string
	seen := func(p string, list []string) bool {
		for _, q := range list {
			if e.Same(p, q) {
				return true
			}
		}
		return false
	}
	for _, p := range paths {
		if !seen(p, out) && !seen(p, drop) {
			out = append(out, p)
		}
	}
	return out
}

// Same reports whether two paths name the same place, ignoring case where
// the OS usually does.
func (e Env) Same(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if e.GOOS == "windows" || e.GOOS == "darwin" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// Item is a file or directory conch keeps.
type Item struct {
	what string // in messages
	kind Kind
	name string // under the kind's directory
	dir  bool   // a directory, which is there once it holds a file
}

func (it Item) What() string { return it.what }
func (it Item) Kind() Kind   { return it.kind }
func (it Item) Name() string { return it.name }
func (it Item) IsDir() bool  { return it.dir }

var (
	profileItem  = Item{"profile.yaml", Config, "profile.yaml", false}
	envItem      = Item{".env", Config, ".env", false}
	pairingsItem = Item{"浏览器扩展的配对 pairings.json", Data, "pairings.json", false}
	stateItem    = Item{"state.json", State, "state.json", false}
	apiItem      = Item{"api.json", State, "api.json", false}
	agentItem    = Item{"agent.json", State, "agent.json", false}
	daemonLog    = Item{"daemon.log", State, "daemon.log", false}
	agentLog     = Item{"agent.log", State, "agent.log", false}
	kernelsItem  = Item{"已下载的内核", Data, "kernels", true}
	homesItem    = Item{"内核的工作目录（geodata）", Data, "home", true}
	listsItem    = Item{"下载的规则列表", Data, "lists", true}
	subsItem     = Item{"下载的订阅", Data, "subscriptions", true}
	certsItem    = Item{"取到的证书 certs.json", Data, "certs.json", false}
)

// Items lists every item, configuration first.
func Items() []Item {
	return []Item{profileItem, envItem, pairingsItem, stateItem, apiItem, agentItem, daemonLog, agentLog,
		kernelsItem, homesItem, listsItem, subsItem, certsItem}
}

// ItemNamed finds the item with a name under its kind's directory.
func ItemNamed(name string) (Item, bool) {
	for _, it := range Items() {
		if it.name == name {
			return it, true
		}
	}
	return Item{}, false
}

// New is the new place of an item.
func (e Env) New(it Item) string { return filepath.Join(e.Dir(it.kind), it.name) }

// Legacy lists the places released versions kept an item, other than the
// new one. There are none with an override set.
func (e Env) Legacy(it Item) []string {
	dirs := e.OldDataDirs()
	if it.kind == Config {
		dirs = e.OldConfigDirs()
	}
	var out []string
	for _, d := range dirs {
		out = append(out, filepath.Join(d, it.name))
	}
	if it == daemonLog {
		for _, d := range e.OldLogDirs() {
			out = append(out, filepath.Join(d, it.name))
		}
	}
	return e.without(out, e.New(it))
}

// Resolve finds an item: at its new place when an override is set or it
// is there; else at an old place where it is, which Notify hears about;
// else at its new place, to be created when first written.
func (e Env) Resolve(it Item) string {
	p := e.New(it)
	if d, _ := e.Override(it.kind); d != "" || Exists(p, it.dir) {
		return p
	}
	for _, old := range e.Legacy(it) {
		if Exists(old, it.dir) {
			if e.Notify != nil {
				e.Notify(it.what, old, p)
			} else {
				notify(it.what, old, p)
			}
			return old
		}
	}
	return p
}

// Exists reports whether an item is at path: a file, or a directory with a
// file somewhere in it. An empty directory a newer version made does not
// hide one at an old place.
func Exists(path string, dir bool) bool {
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() != dir {
		return false
	}
	if !dir {
		return true
	}
	found := errors.New("found")
	err = filepath.WalkDir(path, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			return found
		}
		return nil
	})
	return err == found
}

func (e Env) Profile() string       { return e.Resolve(profileItem) }
func (e Env) EnvFile() string       { return e.Resolve(envItem) }
func (e Env) Pairings() string      { return e.Resolve(pairingsItem) }
func (e Env) StateFile() string     { return e.Resolve(stateItem) }
func (e Env) APIRecord() string     { return e.Resolve(apiItem) }
func (e Env) AgentState() string    { return e.Resolve(agentItem) }
func (e Env) DaemonLog() string     { return e.Resolve(daemonLog) }
func (e Env) AgentLog() string      { return e.Resolve(agentLog) }
func (e Env) Kernels() string       { return e.Resolve(kernelsItem) }
func (e Env) Homes() string         { return e.Resolve(homesItem) }
func (e Env) Lists() string         { return e.Resolve(listsItem) }
func (e Env) Subscriptions() string { return e.Resolve(subsItem) }
func (e Env) Certs() string         { return e.Resolve(certsItem) }

// NewEnvFile is where a new .env goes: in the configuration directory.
func (e Env) NewEnvFile() string { return e.New(envItem) }

// NewDaemonLog is where the daemon's log goes once migrated.
func (e Env) NewDaemonLog() string { return e.New(daemonLog) }

// The same, for this process.

// ConfigDir is the configuration directory, where `conch init` writes the
// profile and a new .env goes.
func ConfigDir() string { return System().Dir(Config) }

// DataDir and StateDir are the other kinds' directories.
func DataDir() string  { return System().Dir(Data) }
func StateDir() string { return System().Dir(State) }

// RunDir is where the kernels' sockets and pid files go.
func RunDir() string { return System().RunDir() }

// OldRunDirs are where earlier versions kept pid files.
func OldRunDirs() []string { return System().OldRunDirs() }

func Profile() string       { return System().Profile() }
func EnvFile() string       { return System().EnvFile() }
func NewEnvFile() string    { return System().NewEnvFile() }
func Pairings() string      { return System().Pairings() }
func StateFile() string     { return System().StateFile() }
func APIRecord() string     { return System().APIRecord() }
func AgentState() string    { return System().AgentState() }
func DaemonLog() string     { return System().DaemonLog() }
func AgentLog() string      { return System().AgentLog() }
func Kernels() string       { return System().Kernels() }
func Homes() string         { return System().Homes() }
func Lists() string         { return System().Lists() }
func Subscriptions() string { return System().Subscriptions() }
func Certs() string         { return System().Certs() }

// KernelHome is the working directory a kernel runs in (its -d), where it
// keeps geodata, rule-set caches and its own state.
func KernelHome(kernel string) string { return filepath.Join(Homes(), kernel) }

var notices = struct {
	sync.Mutex
	w    io.Writer
	seen map[string]bool
}{w: os.Stderr, seen: map[string]bool{}}

// SetNotices sends the lines about old places to w from now on.
// io.Discard silences them, for a TUI that has taken the screen.
func SetNotices(w io.Writer) {
	notices.Lock()
	notices.w = w
	notices.Unlock()
}

func notify(what, old, new string) {
	notices.Lock()
	defer notices.Unlock()
	if notices.seen[what] {
		return
	}
	notices.seen[what] = true
	fmt.Fprintf(notices.w, "conch：正在使用旧位置的 %s（%s）；运行 conch migrate 可以把它移到 %s\n", what, old, new)
}
