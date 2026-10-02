// Package service installs conch as a system service: a daemon that
// starts at boot and may use TUN, plus an agent in each desktop session
// that sets the user's system proxy, which the service cannot.
package service

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/xiongnemo/conch/internal/auth"
)

// Name identifies the service to the OS.
const Name = "conch"

// Layout is where a system-wide installation keeps things.
type Layout struct {
	Bin       string // the conch binary the service runs
	ConfigDir string // profile.yaml, managed.yaml and .env
	DataDir   string // kernels, caches and state
	Log       string // where the service's output goes, if the OS does not keep it
}

// User is who ran the installer (through sudo, or elevated on Windows):
// their profile, kernels and password are carried over, and the agent
// starts in their session.
type User struct {
	Name      string
	UID       string
	Home      string
	ConfigDir string
	DataDir   string
}

// Runner runs a command and returns its output; tests replace it.
type Runner func(name string, args ...string) (string, error)

// Exec runs commands for real, showing their output on failure.
func Exec(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return text, fmt.Errorf("%s %s：%v %s", name, strings.Join(args, " "), err, text)
	}
	return text, nil
}

// Options control an installation.
type Options struct {
	Layout  Layout
	User    *User // nil when it cannot be told who installs
	NoAgent bool
	Run     Runner
	Log     io.Writer
	// Profile is the profile to start the service with if it has none.
	Profile string
	// Exe is the conch binary to install; empty means this one.
	Exe string
	// Root prefixes every system path written to; tests set it.
	Root string
}

func (o *Options) path(p string) string { return filepath.Join(o.Root, p) }

// files is the layout as the installer writes to it.
func (o *Options) files() Layout {
	l := o.Layout
	return Layout{Bin: o.path(l.Bin), ConfigDir: o.path(l.ConfigDir), DataDir: o.path(l.DataDir), Log: o.path(l.Log)}
}

func (o *Options) exe() (string, error) {
	if o.Exe != "" {
		return o.Exe, nil
	}
	return os.Executable()
}

func (o *Options) logf(format string, args ...any) {
	if o.Log != nil {
		fmt.Fprintf(o.Log, format+"\n", args...)
	}
}

// ErrNotInstalled means there is no conch service.
var ErrNotInstalled = errors.New("conch 服务没有安装")

// copyFile copies src to dst with mode, unless they are the same file.
func copyFile(src, dst string, mode fs.FileMode) error {
	if a, err := os.Stat(src); err == nil {
		if b, err := os.Stat(dst); err == nil && os.SameFile(a, b) {
			return nil
		}
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp := dst + ".new"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	// Renaming replaces a binary that is running, which writing over it
	// cannot do. Windows refuses even that, but lets the running binary
	// itself be renamed: it moves aside first.
	if runtime.GOOS == "windows" {
		old := dst + ".old"
		os.Remove(old)
		if os.Rename(dst, old) == nil {
			defer os.Remove(old) // fails while it still runs; the next install retries
		}
	}
	return os.Rename(tmp, dst)
}

// copyTree copies a directory, for carrying installed kernels over.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			return os.MkdirAll(target, 0o755)
		case info.Mode().Type() == fs.ModeSymlink:
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			os.Remove(target)
			return os.Symlink(link, target)
		default:
			return copyFile(path, target, info.Mode().Perm())
		}
	})
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// writeFile writes a file the installer owns, creating its directory.
func writeFile(path string, data []byte, mode fs.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, mode)
}

// carryOver gives the service what the installing user already has: the
// profile (if the service has none) and the downloaded kernels, which
// may be hard to download again without a proxy.
func carryOver(o *Options) error {
	l := o.files()
	if dst := filepath.Join(l.ConfigDir, "profile.yaml"); o.Profile != "" && !exists(dst) {
		if err := copyFile(o.Profile, dst, 0o640); err != nil {
			return err
		}
		o.logf("已把 %s 复制为 %s", o.Profile, dst)
		managed := filepath.Join(filepath.Dir(o.Profile), "managed.yaml")
		if exists(managed) {
			if err := copyFile(managed, filepath.Join(l.ConfigDir, "managed.yaml"), 0o640); err != nil {
				return err
			}
		}
	}
	if o.User != nil {
		src, dst := filepath.Join(o.User.DataDir, "kernels"), filepath.Join(l.DataDir, "kernels")
		if exists(src) && !exists(dst) {
			if err := copyTree(src, dst); err != nil {
				return fmt.Errorf("复制内核：%w", err)
			}
			o.logf("已复制已经下载好的内核")
		}
	}
	return nil
}

// syncPassword gives the service and the installing user the same API
// password, so the user's CLI, TUI and agent can reach the service. The
// service keeps its password; otherwise the user's is used, or a new one.
// It returns the user's .env when it was written.
func syncPassword(o *Options) (string, error) {
	serviceEnv := filepath.Join(o.files().ConfigDir, ".env")
	userEnv := ""
	if o.User != nil {
		userEnv = filepath.Join(o.User.ConfigDir, ".env")
	}
	pw := auth.PasswordIn(serviceEnv)
	if pw == "" && userEnv != "" {
		pw = auth.PasswordIn(userEnv)
	}
	if pw == "" {
		pw = auth.NewPassword()
	}
	if auth.PasswordIn(serviceEnv) != pw {
		if err := auth.SetPassword(serviceEnv, pw); err != nil {
			return "", err
		}
	}
	if userEnv == "" {
		o.logf("登录密码保存在 %s", serviceEnv)
		return "", nil
	}
	if old := auth.PasswordIn(userEnv); old != pw {
		if err := os.MkdirAll(filepath.Dir(userEnv), 0o700); err != nil {
			return "", err
		}
		if err := auth.SetPassword(userEnv, pw); err != nil {
			return "", err
		}
		if old != "" {
			o.logf("%s 里的密码已改成服务的密码", userEnv)
		}
		return userEnv, nil
	}
	return "", nil
}
