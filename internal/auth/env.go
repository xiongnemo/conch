// Package auth protects the daemon's HTTP API and Web UI: settings and the
// password from .env files, login sessions, and request checks that apply
// even when authentication is off.
package auth

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// Settings come from CONCH_* variables.
type Settings struct {
	Password string
	Auth     bool   // CONCH_AUTH, default on
	Listen   string // CONCH_LISTEN, default 127.0.0.1:9277
	TLSCert  string
	TLSKey   string
	// PasswordFile is the .env the password was read from, if any.
	PasswordFile string
}

const DefaultListen = "127.0.0.1:9277"

// EnvFiles lists the .env files in lookup order: the current directory
// first, then the config directory.
func EnvFiles(cwd, configDir string) []string {
	return []string{filepath.Join(cwd, ".env"), filepath.Join(configDir, ".env")}
}

// Load reads settings. For each key the process environment wins, then the
// .env files in order.
func Load(cwd, configDir string) (Settings, error) {
	files := EnvFiles(cwd, configDir)
	values := map[string]string{}
	from := map[string]string{}
	for i := len(files) - 1; i >= 0; i-- { // later files first, earlier override
		kv, err := readEnv(files[i])
		if err != nil {
			return Settings{}, err
		}
		for k, v := range kv {
			values[k], from[k] = v, files[i]
		}
	}
	for _, k := range []string{"CONCH_PASSWORD", "CONCH_AUTH", "CONCH_LISTEN", "CONCH_TLS_CERT", "CONCH_TLS_KEY"} {
		if v, ok := os.LookupEnv(k); ok {
			values[k], from[k] = v, "环境变量"
		}
	}
	s := Settings{
		Password:     values["CONCH_PASSWORD"],
		PasswordFile: from["CONCH_PASSWORD"],
		Listen:       values["CONCH_LISTEN"],
		TLSCert:      values["CONCH_TLS_CERT"],
		TLSKey:       values["CONCH_TLS_KEY"],
		Auth:         true,
	}
	switch strings.ToLower(values["CONCH_AUTH"]) {
	case "", "on", "true", "1", "yes":
	case "off", "false", "0", "no":
		s.Auth = false
	default:
		return s, fmt.Errorf("CONCH_AUTH 应该是 on 或 off，而不是 %q", values["CONCH_AUTH"])
	}
	if s.Listen == "" {
		s.Listen = DefaultListen
	}
	return s, s.check()
}

// check refuses an unauthenticated API on anything but loopback.
func (s Settings) check() error {
	host, _, err := net.SplitHostPort(s.Listen)
	if err != nil {
		return fmt.Errorf("CONCH_LISTEN %q 应该写成 地址:端口", s.Listen)
	}
	if !s.Auth && !IsLoopback(host) {
		return fmt.Errorf("关闭鉴权时只能监听本机地址，而 CONCH_LISTEN 是 %s", s.Listen)
	}
	if (s.TLSCert == "") != (s.TLSKey == "") {
		return errors.New("CONCH_TLS_CERT 和 CONCH_TLS_KEY 需要同时设置")
	}
	return nil
}

// IsLoopback reports whether host only accepts local connections.
func IsLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Ensure creates a password when authentication is on and none is set. It
// is appended to ./.env, or to the config directory's .env when the
// current directory is not writable. It returns the file it wrote to, or
// "" when nothing was needed.
func Ensure(s *Settings, cwd, configDir string) (string, error) {
	if !s.Auth || s.Password != "" {
		return "", nil
	}
	s.Password = NewPassword()
	var lastErr error
	for _, f := range EnvFiles(cwd, configDir) {
		if err := appendEnv(f, "CONCH_PASSWORD", s.Password); err != nil {
			lastErr = err
			continue
		}
		s.PasswordFile = f
		return f, nil
	}
	return "", fmt.Errorf("无法保存生成的密码：%w", lastErr)
}

// SetPassword replaces CONCH_PASSWORD in an .env file, keeping the
// other lines.
func SetPassword(file, password string) error {
	data, err := os.ReadFile(file)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	var lines []string
	replaced := false
	for _, l := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if k, _, ok := parseLine(l); ok && k == "CONCH_PASSWORD" {
			l, replaced = "CONCH_PASSWORD="+password, true
		}
		if l != "" || len(lines) > 0 {
			lines = append(lines, l)
		}
	}
	if !replaced {
		lines = append(lines, "CONCH_PASSWORD="+password)
	}
	return writePrivate(file, []byte(strings.Join(lines, "\n")+"\n"))
}

func appendEnv(file, key, value string) error {
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		return err
	}
	data, err := os.ReadFile(file)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if len(data) > 0 && !strings.HasSuffix(string(data), "\n") {
		data = append(data, '\n')
	}
	return writePrivate(file, append(data, []byte(key+"="+value+"\n")...))
}

func writePrivate(file string, data []byte) error {
	tmp := file + ".part"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, file)
}

func readEnv(file string) (map[string]string, error) {
	f, err := os.Open(file)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	kv := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if k, v, ok := parseLine(sc.Text()); ok {
			kv[k] = v
		}
	}
	return kv, sc.Err()
}

// parseLine reads KEY=VALUE, allowing "export", quotes and # comments.
func parseLine(l string) (string, string, bool) {
	l = strings.TrimSpace(l)
	if l == "" || strings.HasPrefix(l, "#") {
		return "", "", false
	}
	l = strings.TrimPrefix(l, "export ")
	k, v, ok := strings.Cut(l, "=")
	if !ok {
		return "", "", false
	}
	k, v = strings.TrimSpace(k), strings.TrimSpace(v)
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		v = v[1 : len(v)-1]
	} else if i := strings.Index(v, " #"); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	return k, v, true
}

// GitIgnoreWarning returns a hint when file sits in a git work tree whose
// .gitignore does not mention .env, so the password is not committed.
func GitIgnoreWarning(file string) string {
	dir := filepath.Dir(file)
	for d := dir; ; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, ".git")); err == nil {
			ignore, _ := os.ReadFile(filepath.Join(d, ".gitignore"))
			for _, l := range strings.Split(string(ignore), "\n") {
				if t := strings.TrimSpace(l); t == ".env" || t == "/.env" || t == "*.env" {
					return ""
				}
			}
			return fmt.Sprintf("%s 在 git 仓库里，请把 .env 加进 .gitignore，以免把密码提交上去", file)
		}
		if filepath.Dir(d) == d {
			return ""
		}
	}
}

// PasswordIn returns the password a .env file sets, if any.
func PasswordIn(file string) string {
	env, err := readEnv(file)
	if err != nil {
		return ""
	}
	return env["CONCH_PASSWORD"]
}

// NewPassword returns a random password.
func NewPassword() string {
	buf := make([]byte, 18)
	rand.Read(buf)
	return base64.RawURLEncoding.EncodeToString(buf)
}
