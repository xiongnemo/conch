package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const userUnit = "conch.service"

// EnableAutostart starts the daemon at login: a systemd user unit, started
// now too, or without a systemd user session an autostart entry of the
// desktop.
func EnableAutostart(a Autostart) error {
	if _, err := a.Run("systemctl", "--user", "show-environment"); err != nil {
		path := filepath.Join(a.AutostartDir, "conch.desktop")
		if err := writeFile(path, []byte(DesktopEntry(a)), 0o644); err != nil {
			return err
		}
		a.logf("这个系统没有 systemd 用户会话，已改用桌面的自启动项 %s：下次登录桌面时启动；现在可以先运行 conch daemon", path)
		return nil
	}
	if err := writeFile(filepath.Join(a.Dir, userUnit), []byte(SystemdUserUnit(a)), 0o644); err != nil {
		return err
	}
	for _, args := range [][]string{{"--user", "daemon-reload"}, {"--user", "enable", "--now", userUnit}} {
		if _, err := a.Run("systemctl", args...); err != nil {
			return err
		}
	}
	a.logf("已开启：登录后自动运行 conch daemon，现在也已经启动。状态：systemctl --user status conch，日志：journalctl --user -u conch")
	return nil
}

// DisableAutostart stops the daemon started at login and removes it.
func DisableAutostart(a Autostart) error {
	unit, desktop := filepath.Join(a.Dir, userUnit), filepath.Join(a.AutostartDir, "conch.desktop")
	if !exists(unit) && !exists(desktop) {
		return ErrAutostartOff
	}
	if exists(unit) {
		a.Run("systemctl", "--user", "disable", "--now", userUnit)
		if err := os.Remove(unit); err != nil {
			return err
		}
		a.Run("systemctl", "--user", "daemon-reload")
		a.logf("已关闭登录时自动启动，并停止了它启动的 conch daemon")
	}
	if exists(desktop) {
		if err := os.Remove(desktop); err != nil {
			return err
		}
		a.logf("已关闭登录时自动启动；正在运行的 conch daemon 不受影响")
	}
	return nil
}

// ReadAutostart reads what autostart starts: the systemd user unit, or
// the desktop's autostart entry.
func ReadAutostart(a Autostart) (Registered, error) {
	for _, f := range []struct{ path, key string }{{filepath.Join(a.Dir, userUnit), "ExecStart"}, {filepath.Join(a.AutostartDir, "conch.desktop"), "Exec"}} {
		data, err := os.ReadFile(f.path)
		if err != nil {
			continue
		}
		v, _ := keyLine(string(data), f.key)
		if f.key == "Exec" {
			return Registered{Args: parseDesktopExec(v), Where: f.path}, nil
		}
		return Registered{Args: parseSystemdExec(v), Where: f.path}, nil
	}
	return Registered{}, ErrAutostartOff
}

// RewriteAutostart writes what r was registered as again for a, in the
// same place. It starts nothing: a unit takes effect at its next start.
func RewriteAutostart(a Autostart, r Registered) error {
	if filepath.Base(r.Where) == "conch.desktop" {
		return writeFile(r.Where, []byte(DesktopEntry(a)), 0o644)
	}
	if err := writeFile(r.Where, []byte(SystemdUserUnit(a)), 0o644); err != nil {
		return err
	}
	_, err := a.Run("systemctl", "--user", "daemon-reload")
	return err
}

// AutostartStatus describes autostart in a line.
func AutostartStatus(a Autostart) (string, error) {
	if exists(filepath.Join(a.Dir, userUnit)) {
		active, _ := a.Run("systemctl", "--user", "is-active", userUnit)
		return fmt.Sprintf("已开启（systemd 用户服务 conch.service）：%s", strings.TrimSpace(active)), nil
	}
	if path := filepath.Join(a.AutostartDir, "conch.desktop"); exists(path) {
		return "已开启（桌面自启动项 " + path + "）", nil
	}
	return "", ErrAutostartOff
}
