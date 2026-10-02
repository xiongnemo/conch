package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	"github.com/xiongnemo/conch/internal/auth"
	"github.com/xiongnemo/conch/internal/paths"
	"github.com/xiongnemo/conch/internal/platform/service"
)

func newServiceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "service",
		Short: "把 conch 装成系统服务：开机启动，可以开启 TUN",
		Long: `把 conch 装成系统服务（Linux 用 systemd，macOS 用 launchd，Windows 用服务管理器）。
服务开机启动，并且有开启 TUN 需要的权限；每个用户登录后，conch agent 会替服务设置这个用户的系统代理。
安装时会带上你现在的 profile、已下载的内核和登录密码。需要用 sudo（Windows 上以管理员身份）运行。`,
	}
	var noAgent bool
	install := &cobra.Command{
		Use:   "install",
		Short: "安装并启动服务",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			o, err := serviceOptions(cmd)
			if err != nil {
				return err
			}
			o.NoAgent = noAgent
			// A packaged binary (deb, rpm, Homebrew) stays where it is.
			if exe, err := os.Executable(); err == nil && runtime.GOOS != "windows" {
				switch filepath.Dir(exe) {
				case "/usr/bin", "/usr/local/bin", "/opt/homebrew/bin":
					o.Layout.Bin = exe
				}
			}
			if u := o.User; u != nil {
				if p, err := resolveProfile(""); err == nil {
					o.Profile = p
				} else if p := filepath.Join(u.ConfigDir, "profile.yaml"); fileExists(p) {
					o.Profile = p
				}
			}
			if c, err := net.DialTimeout("tcp", auth.DefaultListen, time.Second); err == nil {
				c.Close()
				fmt.Fprintf(cmd.ErrOrStderr(), "注意：%s 已经有程序在监听，可能是你自己运行的 conch daemon；请先停掉它，否则服务无法使用这个端口\n", auth.DefaultListen)
			}
			if err := service.Install(o); err != nil {
				return err
			}
			l := o.Layout
			fmt.Fprintf(cmd.OutOrStdout(), "完成。配置文件在 %s，修改后服务会自动应用；Web UI：http://%s/\n", filepath.Join(l.ConfigDir, "profile.yaml"), auth.DefaultListen)
			return nil
		},
	}
	install.Flags().BoolVar(&noAgent, "no-agent", false, "不安装设置系统代理的 agent（例如没有桌面的服务器）")
	uninstall := &cobra.Command{
		Use:   "uninstall",
		Short: "停止并卸载服务（保留配置和数据）",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			o, err := serviceOptions(cmd)
			if err != nil {
				return err
			}
			return service.Uninstall(o)
		},
	}
	status := &cobra.Command{
		Use:   "status",
		Short: "查看服务的状态",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			o := service.Options{Layout: service.SystemLayout(), Run: service.Exec}
			s, err := service.Status(o)
			if errors.Is(err, service.ErrNotInstalled) {
				fmt.Fprintln(cmd.OutOrStdout(), "conch 服务没有安装")
				return nil
			}
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), s)
			return nil
		},
	}
	cmd.AddCommand(install, uninstall, status)
	return cmd
}

// serviceOptions finds who is installing: the user behind sudo, or on
// Windows the elevated user themselves.
func serviceOptions(cmd *cobra.Command) (service.Options, error) {
	o := service.Options{Layout: service.SystemLayout(), Run: service.Exec, Log: cmd.OutOrStdout()}
	var u *user.User
	var err error
	if runtime.GOOS == "windows" {
		u, err = user.Current()
	} else {
		if os.Geteuid() != 0 {
			return o, errors.New("需要 root 权限：sudo conch service " + cmd.Name())
		}
		if name := os.Getenv("SUDO_USER"); name != "" && name != "root" {
			u, err = user.Lookup(name)
		}
	}
	if err != nil {
		return o, err
	}
	if u != nil {
		config, data := paths.UserDirs(u.HomeDir)
		o.User = &service.User{Name: u.Username, UID: u.Uid, Home: u.HomeDir, ConfigDir: config, DataDir: data}
	}
	return o, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
