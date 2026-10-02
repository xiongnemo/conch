package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SystemLayout is where a system-wide installation lives on macOS. The
// daemon runs as root: macOS lets only root create utun devices.
func SystemLayout() Layout {
	base := "/Library/Application Support/conch"
	return Layout{Bin: "/usr/local/bin/conch", ConfigDir: base, DataDir: filepath.Join(base, "data"), Log: "/Library/Logs/conch.log"}
}

var (
	daemonPlist = filepath.Join("/Library/LaunchDaemons", LaunchdDaemon+".plist")
	agentPlist  = filepath.Join("/Library/LaunchAgents", LaunchdAgent+".plist")
)

// Install sets up the launchd daemon and the agent for every session,
// and starts them.
func Install(o Options) error {
	l, files := o.Layout, o.files()
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
		if _, err := o.Run("chown", "-R", o.User.Name, filepath.Dir(userEnv)); err != nil {
			return err
		}
	}
	if err := writeFile(o.path(daemonPlist), []byte(LaunchdDaemonPlist(l)), 0o644); err != nil {
		return err
	}
	o.Run("launchctl", "bootout", "system/"+LaunchdDaemon) // when reinstalling
	if _, err := o.Run("launchctl", "bootstrap", "system", daemonPlist); err != nil {
		return err
	}
	o.logf("conch 服务已启动，日志在 %s", l.Log)
	if o.NoAgent {
		return nil
	}
	if err := writeFile(o.path(agentPlist), []byte(LaunchdAgentPlist(l)), 0o644); err != nil {
		return err
	}
	if o.User != nil {
		domain := "gui/" + o.User.UID
		o.Run("launchctl", "bootout", domain+"/"+LaunchdAgent)
		if _, err := o.Run("launchctl", "bootstrap", domain, agentPlist); err != nil {
			o.logf("没能在当前会话里启动 agent（%v），下次登录时会自动启动", err)
		}
	}
	return nil
}

// Uninstall stops and removes the daemon and the agent, keeping the
// configuration and data.
func Uninstall(o Options) error {
	if !exists(o.path(daemonPlist)) && !exists(o.path(agentPlist)) {
		return ErrNotInstalled
	}
	if o.User != nil {
		o.Run("launchctl", "bootout", "gui/"+o.User.UID+"/"+LaunchdAgent)
	}
	o.Run("launchctl", "bootout", "system/"+LaunchdDaemon)
	for _, p := range []string{daemonPlist, agentPlist} {
		if err := os.Remove(o.path(p)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	l := o.Layout
	o.logf("已卸载 conch 服务。配置和数据还留在 %s，%s 也没有删除", l.ConfigDir, l.Bin)
	return nil
}

// Status describes the service in a line.
func Status(o Options) (string, error) {
	if !exists(o.path(daemonPlist)) {
		return "", ErrNotInstalled
	}
	out, err := o.Run("launchctl", "print", "system/"+LaunchdDaemon)
	if err != nil {
		return LaunchdDaemon + "：已安装，没有运行", nil
	}
	for _, line := range strings.Split(out, "\n") {
		if state, ok := strings.CutPrefix(strings.TrimSpace(line), "state = "); ok {
			return LaunchdDaemon + "：" + state, nil
		}
	}
	return LaunchdDaemon + "：已加载", nil
}
