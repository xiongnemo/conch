package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"nautilus/internal/api"
	"nautilus/internal/auth"
	"nautilus/internal/daemon"
	"nautilus/internal/kernels"
	"nautilus/internal/paths"
	"nautilus/web"
)

// resolveProfile finds the profile: the flag, else ./profile.yaml, else
// the one in the config directory.
func resolveProfile(flag string) (string, error) {
	candidates := []string{flag}
	if flag == "" {
		candidates = []string{"profile.yaml", filepath.Join(paths.ConfigDir(), "profile.yaml")}
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return filepath.Abs(c)
		}
	}
	return "", fmt.Errorf("找不到 profile.yaml（找过 %v），可以参考 examples/profile.yaml 写一份", candidates)
}

func loadSettings() (auth.Settings, string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return auth.Settings{}, "", err
	}
	s, err := auth.Load(cwd, paths.ConfigDir())
	return s, cwd, err
}

func newDaemonCmd() *cobra.Command {
	var (
		profileFlag string
		backendName string
		offline     bool
	)
	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "运行内核，并提供 Web UI 和 API",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.ErrOrStderr()
			settings, cwd, err := loadSettings()
			if err != nil {
				return err
			}
			if file, err := auth.Ensure(&settings, cwd, paths.ConfigDir()); err != nil {
				return err
			} else if file != "" {
				fmt.Fprintf(out, "已生成登录密码，保存在 %s：\n\n    %s\n\n", file, settings.Password)
				if w := auth.GitIgnoreWarning(file); w != "" {
					fmt.Fprintln(out, "注意：", w)
				}
			}
			profile, err := resolveProfile(profileFlag)
			if err != nil {
				return err
			}
			opts := daemon.Options{ProfilePath: profile, DataDir: paths.DataDir(), Backend: backendName, Offline: offline, Log: out}
			d, err := newDaemon(cmd.Context(), opts, out)
			if err != nil {
				return err
			}

			guard := auth.NewGuard(settings)
			srv := &http.Server{Handler: (&api.Server{D: d, Guard: guard, Web: web.FS()}).Handler(), ReadHeaderTimeout: 10 * time.Second}
			ln, err := net.Listen("tcp", settings.Listen)
			if err != nil {
				return fmt.Errorf("Web UI 无法监听 %s：%w", settings.Listen, err)
			}
			go func() {
				var err error
				if settings.TLSCert != "" {
					err = srv.ServeTLS(ln, settings.TLSCert, settings.TLSKey)
				} else {
					err = srv.Serve(ln)
				}
				if err != nil && !errors.Is(err, http.ErrServerClosed) {
					fmt.Fprintln(out, "Web UI 停止了：", err)
				}
			}()
			scheme := "http"
			if settings.TLSCert != "" {
				scheme = "https"
			}
			fmt.Fprintf(out, "Web UI：%s://%s/\n", scheme, displayAddr(settings.Listen))
			if host, _, _ := net.SplitHostPort(settings.Listen); !auth.IsLoopback(host) && settings.TLSCert == "" {
				fmt.Fprintln(out, "警告：Web UI 监听在本机以外的地址，但没有配置 TLS 证书，密码会以明文传输")
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			go followSettings(ctx, guard, cwd, out)
			err = d.Run(ctx)
			shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			srv.Shutdown(shutdown)
			return err
		},
	}
	f := cmd.Flags()
	f.StringVarP(&profileFlag, "profile", "p", "", "profile 文件（默认是当前目录或配置目录里的 profile.yaml）")
	f.StringVar(&backendName, "backend", "", "内核：mihomo 或 xray（默认沿用上次的选择，第一次是 mihomo）")
	f.BoolVar(&offline, "offline", false, "不下载订阅和规则列表，只用已缓存的")
	return cmd
}

// newDaemon creates the daemon, installing the kernel and its geodata the
// first time they are needed.
func newDaemon(ctx context.Context, opts daemon.Options, out io.Writer) (*daemon.Daemon, error) {
	d, err := daemon.New(opts)
	var missing *kernels.NotInstalledError
	if errors.As(err, &missing) && !opts.Offline {
		fmt.Fprintf(out, "第一次使用 %s，正在下载内核……\n", missing.Kernel)
		if _, err := kernels.Install(ctx, kernels.InstallOptions{Kernel: missing.Kernel, Dir: opts.DataDir, Target: kernels.Host(), Log: out}); err != nil {
			return nil, err
		}
		d, err = daemon.New(opts)
	}
	if err != nil {
		return nil, err
	}
	// xray reads geosite:/geoip: categories from its own data files.
	if name := d.Status().Backend; name == "xray" && !kernels.HasGeodata(name, paths.KernelHome(name)) && !opts.Offline {
		fmt.Fprintln(out, "正在下载 xray 需要的 geodata……")
		if err := kernels.FetchGeodata(ctx, nil, name, "", paths.KernelHome(name), out); err != nil {
			return nil, err
		}
	}
	return d, nil
}

// followSettings picks up a changed password from the .env files.
func followSettings(ctx context.Context, guard *auth.Guard, cwd string, out io.Writer) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		s, err := auth.Load(cwd, paths.ConfigDir())
		if err != nil {
			continue
		}
		old := guard.Settings()
		if s.Password != old.Password || s.Auth != old.Auth {
			s.Listen, s.TLSCert, s.TLSKey = old.Listen, old.TLSCert, old.TLSKey // need a restart
			guard.Update(s)
			fmt.Fprintln(out, "登录设置已更新，之前的登录会话已失效")
		}
	}
}

func displayAddr(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return listen
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

func newPasswdCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "passwd [新密码]",
		Short: "修改 Web UI 和 API 的登录密码（不写新密码就随机生成一个）",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			settings, cwd, err := loadSettings()
			if err != nil {
				return err
			}
			password := ""
			if len(args) == 1 {
				password = args[0]
			} else {
				buf := make([]byte, 18)
				rand.Read(buf)
				password = base64.RawURLEncoding.EncodeToString(buf)
			}
			file := settings.PasswordFile
			if file == "" || file == "环境变量" {
				file = filepath.Join(cwd, ".env")
			}
			if err := auth.SetPassword(file, password); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "新密码已保存到 %s：%s\n正在运行的 daemon 会在几秒内改用新密码，之前的登录会话会失效。\n", file, password)
			if settings.PasswordFile == "环境变量" {
				fmt.Fprintln(cmd.ErrOrStderr(), "注意：环境变量 NAUTILUS_PASSWORD 优先于 .env，需要同时修改它")
			}
			return nil
		},
	}
}

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "查看 daemon 的状态",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			settings, _, err := loadSettings()
			if err != nil {
				return err
			}
			s, err := api.NewClient(settings).Status(cmd.Context())
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "内核：%s（%s", s.Backend, s.Kernel.State)
			if s.Kernel.Restarts > 0 {
				fmt.Fprintf(w, "，重启过 %d 次", s.Kernel.Restarts)
			}
			fmt.Fprintf(w, "）\n模式：%s\n代理端口：127.0.0.1:%d\nprofile：%s\n", s.Mode, s.MixedPort, s.Profile)
			if s.Error != "" {
				fmt.Fprintf(w, "配置有问题（内核继续使用上一份可用的配置）：\n%s\n", s.Error)
			}
			return nil
		},
	}
}

func newSysProxyCmd() *cobra.Command {
	set := func(on bool) func(*cobra.Command, []string) error {
		return func(cmd *cobra.Command, _ []string) error {
			if err := daemonClient().SetSysProxy(cmd.Context(), on); err != nil {
				return err
			}
			if on {
				fmt.Fprintln(cmd.OutOrStdout(), "系统代理已开启；daemon 退出时会恢复原来的设置")
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "系统代理已关闭，已恢复原来的设置")
			}
			return nil
		}
	}
	cmd := &cobra.Command{Use: "sysproxy", Short: "开关系统代理（需要 daemon 在运行）"}
	cmd.AddCommand(
		&cobra.Command{Use: "on", Short: "让系统和浏览器使用 nautilus", Args: cobra.NoArgs, RunE: set(true)},
		&cobra.Command{Use: "off", Short: "恢复原来的系统代理设置", Args: cobra.NoArgs, RunE: set(false)},
	)
	return cmd
}
