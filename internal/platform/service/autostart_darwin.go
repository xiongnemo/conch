package service

import (
	"os"
	"path/filepath"
)

func (a Autostart) plistPath() string { return filepath.Join(a.Dir, LaunchdUser+".plist") }

// EnableAutostart starts the daemon at login with a launch agent of the
// user's own, and starts it now.
func EnableAutostart(a Autostart) error {
	if err := os.MkdirAll(filepath.Dir(a.LogFile), 0o700); err != nil {
		return err
	}
	if err := writeFile(a.plistPath(), []byte(LaunchdUserPlist(a)), 0o644); err != nil {
		return err
	}
	domain := "gui/" + a.UID
	a.Run("launchctl", "bootout", domain+"/"+LaunchdUser) // when enabling again
	if _, err := a.Run("launchctl", "bootstrap", domain, a.plistPath()); err != nil {
		return err
	}
	a.logf("已开启：登录后自动运行 conch daemon，现在也已经启动。日志：%s", a.LogFile)
	return nil
}

// DisableAutostart stops the daemon started at login and removes it.
func DisableAutostart(a Autostart) error {
	if !exists(a.plistPath()) {
		return ErrAutostartOff
	}
	a.Run("launchctl", "bootout", "gui/"+a.UID+"/"+LaunchdUser)
	if err := os.Remove(a.plistPath()); err != nil {
		return err
	}
	a.logf("已关闭登录时自动启动，并停止了它启动的 conch daemon")
	return nil
}

// ReadAutostart reads what the user's launch agent starts.
func ReadAutostart(a Autostart) (Registered, error) {
	data, err := os.ReadFile(a.plistPath())
	if err != nil {
		return Registered{}, ErrAutostartOff
	}
	args, log := parsePlist(string(data))
	return Registered{Args: args, LogFile: log, Where: a.plistPath()}, nil
}

// RewriteAutostart writes the launch agent again for a. launchd reads it
// at the next login, or when it is bootstrapped again.
func RewriteAutostart(a Autostart, r Registered) error {
	if err := os.MkdirAll(filepath.Dir(a.LogFile), 0o700); err != nil {
		return err
	}
	return writeFile(r.Where, []byte(LaunchdUserPlist(a)), 0o644)
}

// AutostartStatus describes autostart in a line.
func AutostartStatus(a Autostart) (string, error) {
	if !exists(a.plistPath()) {
		return "", ErrAutostartOff
	}
	if _, err := a.Run("launchctl", "print", "gui/"+a.UID+"/"+LaunchdUser); err != nil {
		return "已开启（" + a.plistPath() + "），但现在没有在运行", nil
	}
	return "已开启（" + a.plistPath() + "），正在运行", nil
}
