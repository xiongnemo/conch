package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"nautilus/internal/kernels"
)

// SystemLayout is where a system-wide installation lives on Windows.
func SystemLayout() Layout {
	data := filepath.Join(cmpOr(os.Getenv("ProgramData"), `C:\ProgramData`), "nautilus")
	return Layout{
		Bin:       filepath.Join(cmpOr(os.Getenv("ProgramFiles"), `C:\Program Files`), "nautilus", "nautilus.exe"),
		ConfigDir: data,
		DataDir:   filepath.Join(data, "data"),
		Log:       filepath.Join(data, "nautilus.log"),
	}
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

const (
	runKey       = `Software\Microsoft\Windows\CurrentVersion\Run`
	agentValue   = "nautilus-agent"
	firewallRule = "Nautilus kernel"
)

// Install registers and starts the Windows service and starts the agent
// at the installing user's logon.
func Install(o Options) error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("需要以管理员身份运行")
	}
	l := o.Layout
	exe, err := o.exe()
	if err != nil {
		return err
	}
	if err := copyFile(exe, l.Bin, 0o755); err != nil {
		return fmt.Errorf("安装 %s：%w", l.Bin, err)
	}
	for _, d := range []string{l.ConfigDir, l.DataDir} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return err
		}
	}
	if err := carryOver(&o); err != nil {
		return err
	}
	if _, err := syncPassword(&o); err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	if old, err := m.OpenService(Name); err == nil {
		stop(old)
		old.Delete()
		old.Close()
		time.Sleep(time.Second) // deletion completes once handles close
	}
	s, err := m.CreateService(Name, l.Bin, mgr.Config{
		DisplayName: "Nautilus",
		Description: "Nautilus 代理：分流、链式代理和 TUN",
		StartType:   mgr.StartAutomatic,
	}, "daemon", "--service", "--config-dir", l.ConfigDir, "--data-dir", l.DataDir)
	if err != nil {
		return fmt.Errorf("创建服务：%w", err)
	}
	defer s.Close()
	s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 5 * time.Second}}, 86400)
	if err := s.Start(); err != nil {
		return fmt.Errorf("启动服务：%w", err)
	}
	o.logf("nautilus 服务已启动，日志在 %s", l.Log)
	// TUN's system stack accepts connections in the kernel process.
	if inst, err := kernels.Current(l.DataDir, "mihomo", "windows"); err == nil {
		o.Run("netsh", "advfirewall", "firewall", "delete", "rule", "name="+firewallRule)
		if _, err := o.Run("netsh", "advfirewall", "firewall", "add", "rule", "name="+firewallRule, "dir=in", "action=allow", "program="+inst.Path, "enable=yes"); err != nil {
			o.logf("没能在防火墙里放行内核（%v），开启 TUN 时可能需要手动放行", err)
		}
	}
	if o.NoAgent {
		return nil
	}
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.SetStringValue(agentValue, fmt.Sprintf(`"%s" agent`, l.Bin)); err != nil {
		return err
	}
	o.logf("agent 会在下次登录时自动启动；现在可以先运行 nautilus agent")
	return nil
}

func stop(s *mgr.Service) {
	status, err := s.Control(svc.Stop)
	for deadline := time.Now().Add(10 * time.Second); err == nil && status.State != svc.Stopped && time.Now().Before(deadline); {
		time.Sleep(300 * time.Millisecond)
		status, err = s.Query()
	}
}

// Uninstall stops and removes the service and the agent, keeping the
// configuration and data.
func Uninstall(o Options) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(Name)
	if err != nil {
		return ErrNotInstalled
	}
	stop(s)
	err = s.Delete()
	s.Close()
	if err != nil {
		return err
	}
	o.Run("netsh", "advfirewall", "firewall", "delete", "rule", "name="+firewallRule)
	if k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE); err == nil {
		k.DeleteValue(agentValue)
		k.Close()
	}
	o.logf("已卸载 nautilus 服务。配置和数据还留在 %s", o.Layout.ConfigDir)
	return nil
}

// Status describes the service in a line.
func Status(o Options) (string, error) {
	m, err := mgr.Connect()
	if err != nil {
		return "", err
	}
	defer m.Disconnect()
	s, err := m.OpenService(Name)
	if err != nil {
		return "", ErrNotInstalled
	}
	defer s.Close()
	q, err := s.Query()
	if err != nil {
		return "", err
	}
	states := map[svc.State]string{svc.Running: "运行中", svc.Stopped: "已停止", svc.StartPending: "正在启动", svc.StopPending: "正在停止"}
	return "nautilus 服务：" + cmpOr(states[q.State], fmt.Sprint(q.State)), nil
}
