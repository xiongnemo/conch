package service

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
)

// SystemLayout is where a system-wide installation lives on Linux.
func SystemLayout() Layout {
	return Layout{Bin: "/usr/local/bin/nautilus", ConfigDir: "/etc/nautilus", DataDir: "/var/lib/nautilus"}
}

const (
	unitPath      = "/etc/systemd/system/nautilus.service"
	agentUnitPath = "/etc/systemd/user/nautilus-agent.service"
	serviceUser   = "nautilus"
)

var lookupUser = user.Lookup

// Install sets up the systemd service and, unless told not to, the agent
// for every desktop session, and starts them.
func Install(o Options) error {
	if o.Root == "" {
		if _, err := exec.LookPath("systemctl"); err != nil {
			return fmt.Errorf("这个系统没有 systemd，nautilus 还不能把自己装成服务")
		}
	}
	l, files := o.Layout, o.files()
	if _, err := lookupUser(serviceUser); err != nil {
		if _, err := o.Run("useradd", "--system", "--user-group", "--home-dir", l.DataDir, "--no-create-home", "--shell", "/usr/sbin/nologin", serviceUser); err != nil {
			return err
		}
		o.logf("已创建系统用户 %s", serviceUser)
	}
	exe, err := o.exe()
	if err != nil {
		return err
	}
	if err := copyFile(exe, files.Bin, 0o755); err != nil {
		return fmt.Errorf("安装 %s：%w", l.Bin, err)
	}
	for _, d := range []string{files.ConfigDir, files.DataDir} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return err
		}
	}
	if err := carryOver(&o); err != nil {
		return err
	}
	userEnv, err := syncPassword(&o)
	if err != nil {
		return err
	}
	if userEnv != "" {
		if _, err := o.Run("chown", "-R", o.User.Name+":", filepath.Dir(userEnv)); err != nil {
			return err
		}
	}
	if _, err := o.Run("chown", "-R", serviceUser+":"+serviceUser, l.ConfigDir, l.DataDir); err != nil {
		return err
	}
	if err := writeFile(o.path(unitPath), []byte(SystemdUnit(l)), 0o644); err != nil {
		return err
	}
	if !o.NoAgent {
		if err := writeFile(o.path(agentUnitPath), []byte(SystemdAgentUnit(l)), 0o644); err != nil {
			return err
		}
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", "--now", "nautilus.service"}} {
		if _, err := o.Run("systemctl", args...); err != nil {
			return err
		}
	}
	o.logf("nautilus 服务已启动：sudo systemctl status nautilus，日志：journalctl -u nautilus")
	if o.NoAgent {
		return nil
	}
	if _, err := o.Run("systemctl", "--global", "enable", "nautilus-agent.service"); err != nil {
		return err
	}
	if o.User != nil {
		// Start it in the installing user's running session too.
		if _, err := o.Run("systemctl", "--user", "--machine", o.User.Name+"@", "start", "nautilus-agent.service"); err != nil {
			o.logf("没能在当前会话里启动 agent（%v），下次登录时会自动启动", err)
		}
	}
	return nil
}

// Uninstall stops and removes the service and the agent, keeping the
// configuration and data.
func Uninstall(o Options) error {
	if !exists(o.path(unitPath)) && !exists(o.path(agentUnitPath)) {
		return ErrNotInstalled
	}
	if o.User != nil {
		o.Run("systemctl", "--user", "--machine", o.User.Name+"@", "stop", "nautilus-agent.service")
	}
	o.Run("systemctl", "--global", "disable", "nautilus-agent.service")
	o.Run("systemctl", "disable", "--now", "nautilus.service")
	for _, p := range []string{unitPath, agentUnitPath} {
		if err := os.Remove(o.path(p)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if _, err := o.Run("systemctl", "daemon-reload"); err != nil {
		return err
	}
	l := o.Layout
	o.logf("已卸载 nautilus 服务。配置和数据还留在 %s 和 %s，%s 也没有删除", l.ConfigDir, l.DataDir, l.Bin)
	return nil
}

// Status describes the service in a line.
func Status(o Options) (string, error) {
	if !exists(o.path(unitPath)) {
		return "", ErrNotInstalled
	}
	active, _ := o.Run("systemctl", "is-active", "nautilus.service")
	enabled, _ := o.Run("systemctl", "is-enabled", "nautilus.service")
	return fmt.Sprintf("nautilus.service：%s，开机启动：%s", strings.TrimSpace(active), strings.TrimSpace(enabled)), nil
}
