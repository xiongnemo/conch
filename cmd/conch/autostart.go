package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/xiongnemo/conch/internal/auth"
	"github.com/xiongnemo/conch/internal/paths"
	"github.com/xiongnemo/conch/internal/platform/service"
)

func newAutostartCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "autostart",
		Short: "登录时自动运行 conch daemon（不需要管理员权限）",
		Long: `登录后以你自己的身份自动运行 conch daemon，和你在终端里运行 conch daemon 一样：用你的 profile、
内核和密码，启动时只是 HTTP + SOCKS5 代理。不需要 sudo 或管理员权限。
Linux 用 systemd 用户服务（没有的话用桌面的自启动项），macOS 用 LaunchAgent，Windows 用注册表的 Run 项。
需要开机就运行（还没登录时）或者用 TUN，请改用 conch service install。`,
	}
	on := &cobra.Command{
		Use:   "on",
		Short: "开启：登录时自动运行，现在也启动",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := autostartOptions(cmd)
			if err != nil {
				return err
			}
			if _, err := service.Status(service.Options{Layout: service.SystemLayout(), Run: service.Exec}); err == nil {
				return errors.New("已经装了 conch 系统服务，它开机就会运行，不需要再开自动启动。想改用自动启动，先卸载服务：" + uninstallHint())
			}
			if a.Profile, err = resolveProfile(""); err != nil {
				return fmt.Errorf("%w\n先运行 conch init 生成 profile", err)
			}
			if a.Profile, err = filepath.Abs(a.Profile); err != nil {
				return err
			}
			if c, err := net.DialTimeout("tcp", auth.DefaultListen, time.Second); err == nil {
				c.Close()
				fmt.Fprintf(cmd.ErrOrStderr(), "注意：%s 已经有程序在监听，可能是你自己运行的 conch daemon；先停掉它，自动启动的 daemon 才能用这个端口\n", auth.DefaultListen)
			}
			if err := service.EnableAutostart(a); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "使用的 profile：%s\n", a.Profile)
			return nil
		},
	}
	off := &cobra.Command{
		Use:   "off",
		Short: "关闭登录时自动运行",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := autostartOptions(cmd)
			if err != nil {
				return err
			}
			if err := service.DisableAutostart(a); errors.Is(err, service.ErrAutostartOff) {
				fmt.Fprintln(cmd.OutOrStdout(), err)
				return nil
			} else if err != nil {
				return err
			}
			return nil
		},
	}
	status := &cobra.Command{
		Use:   "status",
		Short: "查看是否开启了登录时自动运行",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := autostartOptions(cmd)
			if err != nil {
				return err
			}
			s, err := service.AutostartStatus(a)
			if errors.Is(err, service.ErrAutostartOff) {
				s, err = err.Error(), nil
			}
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), s)
			return nil
		},
	}
	cmd.AddCommand(on, off, status)
	return cmd
}

// autostartOptions is autostart for the user running conch.
func autostartOptions(cmd *cobra.Command) (service.Autostart, error) {
	a := service.Autostart{Run: service.Exec, Log: cmd.OutOrStdout()}
	if runtime.GOOS != "windows" && os.Geteuid() == 0 {
		return a, errors.New("自动启动是每个用户自己的设置，不要用 sudo 运行；需要以 root 开机运行请用 sudo conch service install")
	}
	exe, err := os.Executable()
	if err != nil {
		return a, err
	}
	// Not resolving links: Homebrew's link outlives each version.
	a.Bin = exe
	if tmp, err := filepath.EvalSymlinks(os.TempDir()); err == nil && strings.HasPrefix(exe, tmp) || strings.HasPrefix(exe, os.TempDir()) {
		return a, errors.New("这个 conch 在临时目录里（例如 go run 编译出来的），下次登录时可能已经不在了；请用安装好的 conch 运行")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return a, err
	}
	switch runtime.GOOS {
	case "linux":
		config, err := os.UserConfigDir()
		if err != nil {
			return a, err
		}
		a.Dir, a.AutostartDir = filepath.Join(config, "systemd", "user"), filepath.Join(config, "autostart")
	case "darwin":
		a.Dir = filepath.Join(home, "Library", "LaunchAgents")
		a.LogFile = filepath.Join(home, "Library", "Logs", "conch", "daemon.log")
		a.UID = strconv.Itoa(os.Getuid())
	case "windows":
		a.LogFile = filepath.Join(paths.DataDir(), "daemon.log")
	}
	return a, nil
}

func uninstallHint() string {
	if runtime.GOOS == "windows" {
		return "以管理员身份运行 conch service uninstall"
	}
	return "sudo conch service uninstall"
}
