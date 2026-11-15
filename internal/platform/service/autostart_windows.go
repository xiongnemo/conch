package service

import (
	"errors"
	"os/exec"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const autostartValue = "conch"

// EnableAutostart starts the daemon at login from the user's Run key, and
// starts it now. With --autostart it closes the console window Windows
// opens for it and logs to daemon.log.
func EnableAutostart(a Autostart) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.SetStringValue(autostartValue, windows.ComposeCommandLine(a.Args())); err != nil {
		return err
	}
	args := a.Args()
	cmd := exec.Command(args[0], args[1:]...)
	cmd.SysProcAttr = &windows.SysProcAttr{CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP}
	if err := cmd.Start(); err != nil {
		a.logf("已开启：下次登录时自动运行 conch daemon。现在没能启动它（%v），可以先运行 conch daemon", err)
		return nil
	}
	cmd.Process.Release()
	a.logf("已开启：登录后自动运行 conch daemon，现在也已经在后台启动，日志在 %s", a.LogFile)
	return nil
}

// DisableAutostart removes the daemon from the Run key. A daemon already
// running goes on until it is stopped or the user logs off.
func DisableAutostart(a Autostart) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE|registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return ErrAutostartOff
	}
	if err != nil {
		return err
	}
	defer k.Close()
	if _, _, err := k.GetStringValue(autostartValue); errors.Is(err, registry.ErrNotExist) {
		return ErrAutostartOff
	}
	if err := k.DeleteValue(autostartValue); err != nil {
		return err
	}
	a.logf("已关闭登录时自动启动；正在后台运行的 conch daemon 会一直运行到注销，也可以在任务管理器里结束 conch.exe")
	return nil
}

// AutostartStatus describes autostart in a line.
func AutostartStatus(a Autostart) (string, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return "", ErrAutostartOff
	}
	if err != nil {
		return "", err
	}
	defer k.Close()
	cmd, _, err := k.GetStringValue(autostartValue)
	if errors.Is(err, registry.ErrNotExist) {
		return "", ErrAutostartOff
	}
	if err != nil {
		return "", err
	}
	return "已开启（登录时运行 " + cmd + "）", nil
}
