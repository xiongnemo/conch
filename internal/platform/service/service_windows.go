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

	"github.com/xiongnemo/conch/internal/platform/firewall"
)

// SystemLayout is where a system-wide installation lives on Windows.
func SystemLayout() Layout {
	data := filepath.Join(cmpOr(os.Getenv("ProgramData"), `C:\ProgramData`), "conch")
	return Layout{
		Bin:       filepath.Join(cmpOr(os.Getenv("ProgramFiles"), `C:\Program Files`), "conch", "conch.exe"),
		ConfigDir: data,
		DataDir:   filepath.Join(data, "data"),
		Log:       filepath.Join(data, "conch.log"),
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
	agentValue   = "conch-agent"
	firewallRule = "Conch kernel"
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
	// ProgramData lets every user read what is in it, and .env holds the
	// API password: only SYSTEM and administrators get in.
	if _, err := o.Run("icacls", l.ConfigDir, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "/grant:r", "*S-1-5-32-544:(OI)(CI)F", "/Q"); err != nil {
		o.logf("没能收紧 %s 的权限（%v）：其他用户也许能读到登录密码", l.ConfigDir, err)
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
		DisplayName: "Conch",
		Description: "Conch 代理：分流、链式代理和 TUN",
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
	o.logf("conch 服务已启动，日志在 %s", l.Log)
	// The daemon lets the kernel through the firewall when it turns TUN
	// on; this name is what versions before that used.
	o.Run("netsh", "advfirewall", "firewall", "delete", "rule", "name="+firewallRule)
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
	o.logf("agent 会在下次登录时自动启动；现在可以先运行 conch agent")
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
	firewall.Remove()
	if k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE); err == nil {
		k.DeleteValue(agentValue)
		k.Close()
	}
	o.logf("已卸载 conch 服务。配置和数据还留在 %s", o.Layout.ConfigDir)
	return nil
}

// Status describes the service in a line. It asks only for the right to
// read the status, which every user has.
func Status(o Options) (string, error) {
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return "", err
	}
	defer windows.CloseServiceHandle(m)
	name, _ := windows.UTF16PtrFromString(Name)
	s, err := windows.OpenService(m, name, windows.SERVICE_QUERY_STATUS)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return "", ErrNotInstalled
	} else if err != nil {
		return "", err
	}
	defer windows.CloseServiceHandle(s)
	var q windows.SERVICE_STATUS
	if err := windows.QueryServiceStatus(s, &q); err != nil {
		return "", err
	}
	state := svc.State(q.CurrentState)
	states := map[svc.State]string{svc.Running: "运行中", svc.Stopped: "已停止", svc.StartPending: "正在启动", svc.StopPending: "正在停止"}
	return "conch 服务：" + cmpOr(states[state], fmt.Sprint(state)), nil
}
