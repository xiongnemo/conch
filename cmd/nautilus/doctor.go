package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"nautilus/internal/api"
	"nautilus/internal/daemon"
	"nautilus/internal/kernels"
	"nautilus/internal/paths"
)

func newDoctorCmd() *cobra.Command {
	var fix bool
	var pl pipeline
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "检查常见问题（--fix 修复能自动修复的）",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			d := &doctor{w: cmd.OutOrStdout()}
			ctx := cmd.Context()

			port := 0
			if err := pl.resolve(); err != nil {
				d.bad("%v", err)
			} else {
				pl.offline, pl.log = true, io.Discard
				res, diags, err := pl.compile(ctx)
				switch {
				case err != nil:
					d.bad("profile 无法读取：%v", err)
				case diags.HasErrors():
					d.bad("profile 有错误：\n%s", diags.Err())
				default:
					d.ok("profile 没有问题（%s）", pl.profilePath)
					port = res.Settings.MixedPort
				}
			}

			backend := daemon.LastBackend(paths.DataDir())
			if inst, err := kernels.Current(paths.DataDir(), backend, kernels.Host().OS); err != nil {
				d.bad("%v", err)
			} else {
				d.ok("内核 %s %s 已安装", backend, inst.Version)
			}
			if backend == "xray" && !kernels.HasGeodata("xray", paths.KernelHome("xray")) {
				d.bad("xray 的 geodata 不完整，请运行 nautilus kernel geodata xray")
			}

			settings, _, err := loadSettings()
			if err != nil {
				d.bad("%v", err)
			}
			status, err := api.NewClient(settings).Status(ctx)
			running := err == nil
			switch {
			case running:
				d.ok("daemon 正在运行（%s，内核%s）", status.Backend, status.Kernel.State)
				if status.Error != "" {
					d.bad("daemon 报告配置有问题：%s", status.Error)
				}
			case errors.Is(err, api.ErrNotRunning):
				d.note("daemon 没有在运行")
			default:
				d.bad("无法连接 daemon：%v", err)
			}

			if !running {
				if leftover, p := daemon.SysProxyLeftover(paths.DataDir()); leftover {
					if fix {
						if _, err := daemon.RepairSysProxy(paths.DataDir()); err != nil {
							d.bad("系统代理还指向 127.0.0.1:%d，但恢复失败：%v", p, err)
						} else {
							d.ok("已恢复系统代理设置（之前指向已经停止的 nautilus 127.0.0.1:%d）", p)
						}
					} else {
						d.bad("系统代理还指向 127.0.0.1:%d，但 nautilus 没有在运行，会导致无法上网；运行 nautilus doctor --fix 恢复", p)
					}
				}
				for _, addr := range []string{net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), settings.Listen} {
					if port == 0 || addr == "" {
						continue
					}
					if ln, err := net.Listen("tcp", addr); err != nil {
						d.bad("端口 %s 被其他程序占用", addr)
					} else {
						ln.Close()
					}
				}
			}
			d.clock(ctx)
			if d.failed {
				return errReported
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&fix, "fix", false, "修复能自动修复的问题（目前是残留的系统代理）")
	cmd.Flags().StringVarP(&pl.profilePath, "profile", "p", "", "profile 文件")
	return cmd
}

type doctor struct {
	w      io.Writer
	failed bool
}

func (d *doctor) ok(f string, a ...any)   { fmt.Fprintf(d.w, "✓ "+f+"\n", a...) }
func (d *doctor) note(f string, a ...any) { fmt.Fprintf(d.w, "· "+f+"\n", a...) }
func (d *doctor) bad(f string, a ...any) {
	d.failed = true
	fmt.Fprintf(d.w, "✗ "+f+"\n", a...)
}

// clock compares the local time with a well-known server's: VMess and
// several other protocols fail when the clock is off by more than 90s.
func (d *doctor) clock(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	client := &http.Client{Transport: &http.Transport{Proxy: nil}}
	for _, url := range []string{"https://www.baidu.com", "https://www.gstatic.com/generate_204"} {
		req, _ := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		server, err := http.ParseTime(resp.Header.Get("Date"))
		if err != nil {
			continue
		}
		skew := time.Since(start)/2 + time.Until(server)
		if math.Abs(skew.Seconds()) > 60 {
			d.bad("本机时钟偏差约 %s，VMess 等协议会连不上，请同步时间", skew.Round(time.Second))
		} else {
			d.ok("本机时钟正常（偏差约 %s）", skew.Round(time.Second))
		}
		return
	}
	d.note("无法检查时钟（连不上用来对时的网站）")
}

// proxyPort finds the local proxy port: from the running daemon, else the profile.
func proxyPort(ctx context.Context) (int, error) {
	settings, _, err := loadSettings()
	if err == nil {
		if s, err := api.NewClient(settings).Status(ctx); err == nil && s.MixedPort != 0 {
			return s.MixedPort, nil
		}
	}
	pl := pipeline{offline: true, log: io.Discard}
	if err := pl.resolve(); err != nil {
		return 0, err
	}
	res, _, err := pl.compile(ctx)
	if err != nil {
		return 0, err
	}
	return res.Settings.MixedPort, nil
}

func proxyEnv(port int) [][2]string {
	http := "http://127.0.0.1:" + strconv.Itoa(port)
	return [][2]string{
		{"http_proxy", http}, {"https_proxy", http}, {"HTTP_PROXY", http}, {"HTTPS_PROXY", http},
		{"all_proxy", "socks5h://127.0.0.1:" + strconv.Itoa(port)}, {"ALL_PROXY", "socks5h://127.0.0.1:" + strconv.Itoa(port)},
		{"no_proxy", "localhost,127.0.0.1,::1"}, {"NO_PROXY", "localhost,127.0.0.1,::1"},
	}
}

func newEnvCmd() *cobra.Command {
	var shell string
	cmd := &cobra.Command{
		Use:   "env",
		Short: "打印让命令行程序走 nautilus 的环境变量，例如 eval \"$(nautilus env)\"",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			port, err := proxyPort(cmd.Context())
			if err != nil {
				return err
			}
			for _, kv := range proxyEnv(port) {
				switch shell {
				case "fish":
					fmt.Fprintf(cmd.OutOrStdout(), "set -gx %s %s\n", kv[0], kv[1])
				case "powershell":
					fmt.Fprintf(cmd.OutOrStdout(), "$env:%s = \"%s\"\n", kv[0], kv[1])
				default:
					fmt.Fprintf(cmd.OutOrStdout(), "export %s=%s\n", kv[0], kv[1])
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&shell, "shell", "sh", "sh、fish 或 powershell")
	return cmd
}

func newRunCmd() *cobra.Command {
	return &cobra.Command{
		Use:                "run -- <命令> [参数…]",
		Short:              "让一条命令走 nautilus，例如 nautilus run -- git clone …",
		Args:               cobra.MinimumNArgs(1),
		DisableFlagParsing: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			port, err := proxyPort(cmd.Context())
			if err != nil {
				return err
			}
			c := exec.CommandContext(cmd.Context(), args[0], args[1:]...)
			c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
			c.Env = os.Environ()
			for _, kv := range proxyEnv(port) {
				c.Env = append(c.Env, kv[0]+"="+kv[1])
			}
			err = c.Run()
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				os.Exit(exit.ExitCode())
			}
			if err != nil && strings.Contains(err.Error(), "executable file not found") {
				return fmt.Errorf("找不到命令 %s", args[0])
			}
			return err
		},
	}
}
