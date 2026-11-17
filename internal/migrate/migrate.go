// Package migrate moves what earlier versions of conch kept at the old
// places (see internal/paths) to the new ones: `conch migrate`.
//
// It never overwrites. A directory whose destination exists is merged
// file by file; a file on both sides with the same content leaves only
// the new copy, with different content both stay and it is a conflict.
// Files move with os.Rename, or across volumes are copied (mode and
// modification time kept), checked by size and SHA-256, then removed.
// Old directories left empty are removed, never their parents. Paths into
// the old places in conch's own files and in what the OS starts are
// rewritten. A second run finds nothing to do.
package migrate

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"

	"github.com/xiongnemo/conch/internal/kernel"
	"github.com/xiongnemo/conch/internal/paths"
)

// Options say what to migrate.
type Options struct {
	Env paths.Env
	// From is a .env an earlier version wrote to the directory conch ran
	// in, or that directory: --from, else the current directory.
	From    string
	FromCwd bool // From is the current directory: --from was not given
	DryRun  bool
	Out     io.Writer
	// Registrations are what the OS starts that may point at moved files.
	Registrations []Registration

	rename func(from, to string) error // tests stand in for a move across volumes
}

// Registration is something the OS starts, such as autostart at login.
// Rewrite points it at the new places, given where each moved file went;
// with dryRun it only says what it would change. "" means nothing to do.
type Registration struct {
	Name    string
	Rewrite func(moved func(string) string, dryRun bool) (string, error)
}

// ErrConflicts means some files stayed at both places; each was reported.
var ErrConflicts = errors.New("有文件两边都有而且内容不同，两份都保留了，见上面")

type op int

const (
	opMove     op = iota // From goes to To
	opSame               // From has the content of To: removed
	opConflict           // From and To differ: both stay
	opRegen              // From is made again when needed: removed
)

// step is one thing to do, for one file or for a directory with no
// counterpart at the new place.
type step struct {
	op       op
	from, to string
	root     string // the old directory From is in, emptied ones are removed up to it
	kernels  bool   // downloaded kernels, which lose file capabilities when copied
}

type migration struct {
	Options
	steps []step
	roots []string // old directories some step comes from
	keep  []string // directories never removed: the new ones
}

// Pending counts what is at old places, for `conch doctor`.
func Pending(e paths.Env) int {
	m := &migration{Options: Options{Env: quiet(e)}}
	m.plan()
	return len(m.steps)
}

func quiet(e paths.Env) paths.Env {
	e.Notify = func(string, string, string) {}
	return e
}

// Run migrates, or with DryRun says what it would do. It returns
// ErrConflicts, or the first error, after doing everything else.
func Run(o Options) error {
	if o.rename == nil {
		o.rename = os.Rename
	}
	o.Env = quiet(o.Env)
	m := &migration{Options: o}
	m.header()
	m.plan()
	// What conch's files and the OS hold is read before anything moves.
	refs := m.references()

	verb := map[bool]string{true: "将要", false: "已"}[o.DryRun]
	var firstErr error
	fail := func(err error) {
		fmt.Fprintln(o.Out, "  失败：", err)
		if firstErr == nil {
			firstErr = err
		}
	}
	conflicts, copiedKernels := 0, false
	done := map[string]string{} // what moved, from → to
	if len(m.steps) > 0 {
		fmt.Fprintln(o.Out)
	}
	// Kernels an earlier version left running are ended first: they are
	// told by their binary's path, which is about to change.
	for _, s := range m.steps {
		if s.op == opRegen && !o.DryRun {
			m.endOrphans(s.from)
		}
	}
	for _, s := range m.steps {
		switch s.op {
		case opMove:
			fmt.Fprintf(o.Out, "%s移动 %s → %s\n", verb, s.from, s.to)
			if !o.DryRun {
				copied, err := m.move(s.from, s.to)
				if err != nil {
					fail(err)
					continue
				}
				if copied {
					fmt.Fprintln(o.Out, "  （不在同一个磁盘上：复制并校验后删除了原来的）")
				}
				copiedKernels = copiedKernels || copied && s.kernels
			}
			done[s.from] = s.to
		case opSame:
			fmt.Fprintf(o.Out, "%s删除 %s（和 %s 内容相同）\n", verb, s.from, s.to)
			if !o.DryRun {
				if err := os.Remove(s.from); err != nil {
					fail(err)
					continue
				}
			}
			done[s.from] = s.to
		case opConflict:
			conflicts++
			fmt.Fprintf(o.Out, "冲突：%s 和 %s 内容不同，两份都保留；请自己合并，再删掉旧的\n", s.from, s.to)
		case opRegen:
			fmt.Fprintf(o.Out, "%s删除 %s（运行时文件，daemon 启动时会重新创建）\n", verb, s.from)
			if !o.DryRun {
				if err := os.RemoveAll(s.from); err != nil {
					fail(err)
				}
			}
		}
	}
	if !o.DryRun {
		m.cleanup()
	}
	moved := func(p string) string { return movedPath(o.Env, done, p) }
	rewrites := refs.rewrite(m, moved, fail)
	for _, r := range o.Registrations {
		desc, err := r.Rewrite(moved, o.DryRun)
		switch {
		case err != nil:
			fail(fmt.Errorf("%s：%w；请关掉它再重新打开，让它用新的位置", r.Name, err))
		case desc != "":
			rewrites++
			fmt.Fprintf(o.Out, "%s改写%s：%s\n", verb, r.Name, desc)
		}
	}
	if copiedKernels && runtime.GOOS == "linux" {
		fmt.Fprintln(o.Out, "注意：复制过来的内核没有了 sudo conch kernel setcap 加的权限，不装服务也要用 TUN 的话请再运行一次")
	}
	if len(m.steps) == 0 && rewrites == 0 {
		fmt.Fprintln(o.Out, "\n没有需要迁移的文件。")
	} else if o.DryRun {
		fmt.Fprintln(o.Out, "\n这是预演，什么都没有改动；去掉 --dry-run 就会执行。")
	}
	if firstErr != nil {
		return firstErr
	}
	if conflicts > 0 {
		return ErrConflicts
	}
	return nil
}

// header says where things go now, and where the old .env is looked for.
func (m *migration) header() {
	e := m.Env
	if m.DryRun {
		fmt.Fprintln(m.Out, "预演：只列出要做的事，不改动任何文件。")
	}
	fmt.Fprintln(m.Out, "新的位置：")
	for _, k := range paths.Kinds {
		line := fmt.Sprintf("  %s  %s", k, e.Dir(k))
		if d, name := e.Override(k); d != "" {
			line += fmt.Sprintf("（%s 设置的；旧位置的文件不迁移）", name)
		}
		fmt.Fprintln(m.Out, line)
	}
	if m.From == "" {
		return
	}
	if d, name := e.Override(paths.Config); d != "" {
		fmt.Fprintf(m.Out, "设置了 %s，不迁移 %s 里的 .env\n", name, m.From)
		return
	}
	where := "当前目录"
	if !m.FromCwd {
		where = "--from 给的位置"
	}
	if f := m.fromFile(); f != "" {
		fmt.Fprintf(m.Out, "在%s找到了旧版本写的 .env：%s\n", where, f)
	} else if m.FromCwd {
		fmt.Fprintf(m.Out, "当前目录 %s 里没有旧版本写的 .env（在别的目录运行过 conch daemon 的话，用 --from 指定那个目录）\n", m.From)
	} else {
		fmt.Fprintf(m.Out, "%s 里没有 .env\n", m.From)
	}
}

// fromFile is the .env From names, if it is there and not conch's own.
func (m *migration) fromFile() string {
	f := m.From
	if f == "" {
		return ""
	}
	if fi, err := os.Stat(f); err == nil && fi.IsDir() {
		f = filepath.Join(f, ".env")
	}
	abs, err := filepath.Abs(f)
	if err != nil {
		return ""
	}
	if fi, err := os.Stat(abs); err != nil || fi.IsDir() || m.Env.Same(abs, m.Env.NewEnvFile()) {
		return ""
	}
	if d, _ := m.Env.Override(paths.Config); d != "" {
		return ""
	}
	return abs
}

// plan lists the steps, touching nothing.
func (m *migration) plan() {
	e := m.Env
	for _, k := range paths.Kinds {
		m.keep = append(m.keep, e.Dir(k))
	}
	m.keep = append(m.keep, e.RunDir())
	// Configuration: all of an old directory, the profile's, with what the
	// user keeps next to it.
	for _, dir := range e.OldConfigDirs() {
		m.planDir(dir, func(name string) (string, bool, bool) {
			return filepath.Join(e.Dir(paths.Config), name), false, false
		})
	}
	// The rest: each item to its kind's directory, the run directory away,
	// and what conch does not know as data.
	for _, dir := range e.OldDataDirs() {
		m.planDir(dir, func(name string) (string, bool, bool) {
			if name == "run" {
				return "", true, false
			}
			if it, ok := paths.ItemNamed(name); ok && it.Kind() != paths.Config {
				return e.New(it), false, name == "kernels"
			}
			return filepath.Join(e.Dir(paths.Data), name), false, false
		})
	}
	for _, dir := range e.OldLogDirs() {
		m.planDir(dir, func(name string) (string, bool, bool) {
			return filepath.Join(e.Dir(paths.State), name), false, false
		})
	}
	if f := m.fromFile(); f != "" && !slices.ContainsFunc(m.steps, func(s step) bool { return e.Same(s.from, f) }) {
		m.planMove(f, e.NewEnvFile(), "", false)
	}
}

// planDir plans each entry of an old directory: where it goes, or that it
// is made again when needed.
func (m *migration) planDir(dir string, dest func(name string) (to string, regen, kernels bool)) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	before := len(m.steps)
	for _, ent := range entries {
		from := filepath.Join(dir, ent.Name())
		to, regen, kernels := dest(ent.Name())
		switch {
		case regen:
			if !m.Env.Same(from, m.Env.RunDir()) {
				m.steps = append(m.steps, step{op: opRegen, from: from, root: dir})
			}
		case !m.Env.Same(from, to):
			m.planMove(from, to, dir, kernels)
		}
	}
	if len(m.steps) > before {
		m.roots = append(m.roots, dir)
	}
}

// planMove plans moving from to to: at once when to is not there, else
// merging directories entry by entry and comparing files.
func (m *migration) planMove(from, to, root string, kernels bool) {
	src, err := os.Lstat(from)
	if err != nil {
		return
	}
	dst, err := os.Lstat(to)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		m.steps = append(m.steps, step{op: opMove, from: from, to: to, root: root, kernels: kernels})
	case err != nil:
		m.steps = append(m.steps, step{op: opConflict, from: from, to: to, root: root})
	case src.IsDir() && dst.IsDir():
		entries, _ := os.ReadDir(from)
		for _, ent := range entries {
			m.planMove(filepath.Join(from, ent.Name()), filepath.Join(to, ent.Name()), root, kernels)
		}
	case src.Mode().IsRegular() && dst.Mode().IsRegular() && sameContent(from, to):
		m.steps = append(m.steps, step{op: opSame, from: from, to: to, root: root})
	default:
		m.steps = append(m.steps, step{op: opConflict, from: from, to: to, root: root})
	}
}

func sameContent(a, b string) bool {
	fa, err1 := os.Stat(a)
	fb, err2 := os.Stat(b)
	if err1 != nil || err2 != nil || fa.Size() != fb.Size() {
		return false
	}
	ha, err1 := hashFile(a)
	hb, err2 := hashFile(b)
	return err1 == nil && err2 == nil && ha == hb
}

func hashFile(path string) ([32]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return [32]byte{}, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return [32]byte{}, err
	}
	return [32]byte(h.Sum(nil)), nil
}

// move renames from to to, or across volumes copies, checks and removes
// it. It reports whether it copied.
func (m *migration) move(from, to string) (bool, error) {
	// The new directories are made for the user only: .env and the
	// subscriptions are secrets.
	if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
		return false, err
	}
	err := m.rename(from, to)
	if err == nil || !crossDevice(err) {
		return false, err
	}
	if err := copyTree(from, to); err != nil {
		os.RemoveAll(to) // only what was copied: to was not there
		return true, fmt.Errorf("复制 %s：%w", from, err)
	}
	return true, os.RemoveAll(from)
}

func crossDevice(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	return errno == syscall.EXDEV || runtime.GOOS == "windows" && errno == 17 // ERROR_NOT_SAME_DEVICE
}

// copyTree copies from to the new path to, keeping modes and modification
// times, and checks every file's size and SHA-256.
func copyTree(from, to string) error {
	fi, err := os.Lstat(from)
	if err != nil {
		return err
	}
	switch {
	case fi.Mode()&fs.ModeSymlink != 0:
		link, err := os.Readlink(from)
		if err != nil {
			return err
		}
		return os.Symlink(link, to)
	case fi.IsDir():
		if err := os.Mkdir(to, fi.Mode().Perm()); err != nil {
			return err
		}
		entries, err := os.ReadDir(from)
		if err != nil {
			return err
		}
		for _, ent := range entries {
			if err := copyTree(filepath.Join(from, ent.Name()), filepath.Join(to, ent.Name())); err != nil {
				return err
			}
		}
		return os.Chtimes(to, fi.ModTime(), fi.ModTime())
	}
	return copyFile(from, to, fi)
}

func copyFile(from, to string, fi fs.FileInfo) error {
	src, err := os.Open(from)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fi.Mode().Perm())
	if err != nil {
		return err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(dst, h), src)
	if cerr := dst.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Chmod(to, fi.Mode().Perm()); err != nil {
		return err
	}
	if err := os.Chtimes(to, fi.ModTime(), fi.ModTime()); err != nil {
		return err
	}
	got, err := os.Stat(to)
	if err != nil {
		return err
	}
	sum, err := hashFile(to)
	if err != nil {
		return err
	}
	if got.Size() != fi.Size() || !bytes.Equal(sum[:], h.Sum(nil)) {
		return fmt.Errorf("%s 复制后大小或 SHA-256 对不上", to)
	}
	return nil
}

// endOrphans ends kernels an earlier version's daemon left running, which
// its pid files in dir record: once the kernels move, they could not be
// told by their path any more.
func (m *migration) endOrphans(dir string) {
	pids, _ := filepath.Glob(filepath.Join(dir, "*.pid"))
	for _, p := range pids {
		if kernel.KillOrphan(p) {
			fmt.Fprintf(m.Out, "  已结束上次没有退出的内核（%s）\n", p)
		}
	}
}

// cleanup removes the directories steps left empty, up to and including
// the old directory each came from, which conch owns; never a parent of
// it, nor one of the new directories.
func (m *migration) cleanup() {
	var dirs []string
	seen := map[string]bool{}
	for _, s := range m.steps {
		if s.root == "" {
			continue
		}
		for d := filepath.Dir(s.from); m.within(d, s.root) && !seen[d]; d = filepath.Dir(d) {
			seen[d] = true
			dirs = append(dirs, d)
		}
	}
	// Deepest first: a directory is tried once what was in it is gone.
	slices.SortStableFunc(dirs, func(a, b string) int { return len(b) - len(a) })
	for _, d := range dirs {
		if slices.ContainsFunc(m.keep, func(k string) bool { return m.Env.Same(k, d) }) {
			continue
		}
		if os.Remove(d) == nil { // only an empty one goes
			fmt.Fprintf(m.Out, "已删除空的旧目录 %s\n", d)
		}
	}
}

// within reports whether dir is root or under it.
func (m *migration) within(dir, root string) bool {
	rel, err := filepath.Rel(root, dir)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// movedPath is where p is after the moves done (from → to), p itself if
// it did not move.
func movedPath(e paths.Env, done map[string]string, p string) string {
	if p == "" {
		return p
	}
	best := ""
	for from := range done {
		if (e.Same(p, from) || isUnder(e, p, from)) && len(from) > len(best) {
			best = from
		}
	}
	if best == "" {
		return p
	}
	rel, err := filepath.Rel(best, p)
	if err != nil || rel == "." {
		return done[best]
	}
	return filepath.Join(done[best], rel)
}

func isUnder(e paths.Env, p, dir string) bool {
	p, dir = filepath.Clean(p), filepath.Clean(dir)+string(filepath.Separator)
	if e.GOOS == "windows" || e.GOOS == "darwin" {
		p, dir = strings.ToLower(p), strings.ToLower(dir)
	}
	return strings.HasPrefix(p, dir)
}

// refs are conch's own files that may hold paths into the old places,
// found before anything moves.
type refs struct {
	apiRecords []string // api.json: which .env the daemon read its password from
	envFiles   []string // .env: CONCH_TLS_CERT and CONCH_TLS_KEY
	profiles   []string // profile.yaml and managed.yaml, which conch only reads
}

func (m *migration) references() refs {
	e := m.Env
	var r refs
	for _, it := range paths.Items() {
		places := append([]string{e.New(it)}, e.Legacy(it)...)
		switch it.Name() {
		case "api.json":
			r.apiRecords = append(r.apiRecords, existing(places)...)
		case ".env":
			r.envFiles = append(r.envFiles, existing(places)...)
		case "profile.yaml":
			for _, p := range existing(places) {
				r.profiles = append(r.profiles, p, filepath.Join(filepath.Dir(p), "managed.yaml"))
			}
		}
	}
	if f := m.fromFile(); f != "" {
		r.envFiles = append(r.envFiles, f)
	}
	return r
}

func existing(list []string) []string {
	var out []string
	for _, p := range list {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			out = append(out, p)
		}
	}
	return out
}

// rewrite points paths in conch's files at where the files they name went,
// and says where the profile names an old place. It returns how many
// changes it made or would make.
func (r refs) rewrite(m *migration, moved func(string) string, fail func(error)) int {
	verb := map[bool]string{true: "将要", false: "已"}[m.DryRun]
	n := 0
	// In a dry run nothing moved: the files are read where they are.
	at := func(p string) string {
		if m.DryRun {
			return p
		}
		return moved(p)
	}
	for _, p := range r.apiRecords {
		data, err := os.ReadFile(at(p))
		if err != nil {
			continue
		}
		var rec map[string]any
		if json.Unmarshal(data, &rec) != nil {
			continue
		}
		old, _ := rec["env"].(string)
		if nw := moved(old); nw != old {
			rec["env"] = nw
			n++
			fmt.Fprintf(m.Out, "%s改写 %s 里 .env 的路径：%s → %s\n", verb, at(p), old, nw)
			if !m.DryRun {
				out, _ := json.Marshal(rec)
				if err := writeKeepingMode(at(p), out); err != nil {
					fail(err)
				}
			}
		}
	}
	for _, p := range r.envFiles {
		data, err := os.ReadFile(at(p))
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		changed := false
		for i, l := range lines {
			key, val, ok := strings.Cut(l, "=")
			k := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(key), "export "))
			if !ok || (k != "CONCH_TLS_CERT" && k != "CONCH_TLS_KEY") {
				continue
			}
			v := strings.TrimSpace(val)
			quote := ""
			if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
				quote, v = v[:1], v[1:len(v)-1]
			}
			if nw := moved(v); nw != v {
				lines[i], changed = key+"="+quote+nw+quote, true
				n++
				fmt.Fprintf(m.Out, "%s改写 %s 里的 %s：%s → %s\n", verb, at(p), k, v, nw)
			}
		}
		if changed && !m.DryRun {
			if err := writeKeepingMode(at(p), []byte(strings.Join(lines, "\n"))); err != nil {
				fail(err)
			}
		}
	}
	// The profile is the user's: conch only reads it, so it is not
	// rewritten, but what to change is said.
	for _, p := range r.profiles {
		data, err := os.ReadFile(at(p))
		if err != nil {
			continue
		}
		for i, l := range strings.Split(string(data), "\n") {
			for _, root := range m.roots {
				if mentions(m.Env, l, root) {
					fmt.Fprintf(m.Out, "请修改：%s 第 %d 行提到了旧位置 %s，那里的文件%s移走（见上面）：\n    %s\n", at(p), i+1, root, verb, strings.TrimSpace(l))
				}
			}
		}
	}
	return n
}

// mentions reports whether a line names dir, as written on its OS: with
// forward slashes or doubled backslashes too on Windows.
func mentions(e paths.Env, line, dir string) bool {
	forms := []string{dir}
	if e.GOOS == "windows" {
		forms = append(forms, filepath.ToSlash(dir), strings.ReplaceAll(dir, `\`, `\\`))
	}
	if e.GOOS == "windows" || e.GOOS == "darwin" {
		line = strings.ToLower(line)
	}
	for _, f := range forms {
		if e.GOOS == "windows" || e.GOOS == "darwin" {
			f = strings.ToLower(f)
		}
		if strings.Contains(line, f) {
			return true
		}
	}
	return false
}

// writeKeepingMode replaces a file's content, keeping its mode.
func writeKeepingMode(path string, data []byte) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	tmp := path + ".part"
	if err := os.WriteFile(tmp, data, fi.Mode().Perm()); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
