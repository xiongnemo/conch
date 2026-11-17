package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/xiongnemo/conch/internal/api"
	"github.com/xiongnemo/conch/internal/auth"
	"github.com/xiongnemo/conch/internal/migrate"
	"github.com/xiongnemo/conch/internal/paths"
	"github.com/xiongnemo/conch/internal/platform/service"
)

func newMigrateCmd() *cobra.Command {
	var dryRun bool
	var from string
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "把旧版本放在旧位置的文件移到新的位置（先用 --dry-run 看看）",
		Long: `把旧版本放在旧位置的文件移到新的位置。conch 现在在每个系统上都按 XDG 的目录放文件：

  配置  ~/.config/conch         profile.yaml、managed.yaml、.env
  数据  ~/.local/share/conch    pairings.json（浏览器扩展的配对）、内核、内核的工作目录（geodata）、
                                规则列表、订阅、certs.json：没有网络也要靠它们启动，所以不放在 ~/.cache
  状态  ~/.local/state/conch    state.json、api.json、agent.json、daemon.log、agent.log

设置了 XDG_CONFIG_HOME、XDG_DATA_HOME、XDG_STATE_HOME（必须是绝对路径）时用它们；CONCH_CONFIG_DIR 和
CONCH_DATA_DIR 仍然优先，设置了的那类文件不迁移。迁移之前，旧位置的文件照样能用，每次运行会在 stderr
提醒一次。

旧位置是：Windows 的 %APPDATA%\conch 和 %LOCALAPPDATA%\conch，macOS 的 ~/Library/Application Support/conch
和 ~/Library/Logs/conch，Linux 的 ~/.local/share/conch 里的状态文件；还有旧版本在运行 conch daemon
的目录里生成的 .env：默认看当前目录，别的目录用 --from 指定。（当前目录的 .env 以后仍然会读，而且优先于
配置目录里的，只是新的密码不再写到那里。）

从不覆盖：两边都有的文件，内容相同就删掉旧的，不同就两份都保留并报告冲突，最后以非 0 退出。能用 rename
就 rename，跨磁盘时复制、校验大小和 SHA-256 后再删掉原来的。旧目录空了就删掉。api.json、.env 和登录时
自动启动里指向旧位置的路径会改成新的；profile 里提到旧位置的地方会列出来，请自己改。

daemon 在运行时不迁移。conch agent、conch tui 等其他 conch 命令检测不到，请先退出它们。`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			paths.SetNotices(io.Discard) // the old places are what this is about
			o := migrate.Options{Env: paths.System(), From: from, DryRun: dryRun, Out: cmd.OutOrStdout(), Registrations: registrations()}
			if from == "" {
				cwd, err := os.Getwd()
				if err != nil {
					return err
				}
				o.From, o.FromCwd = cwd, true
			} else if _, err := os.Stat(from); err != nil {
				return fmt.Errorf("找不到 --from 给的 %s", from)
			}
			if listen, running := runningDaemon(cmd.Context()); running {
				if !dryRun {
					return errors.New(stopDaemonHint(listen))
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "注意：conch daemon 正在运行（%s），真正迁移之前要先停掉它\n", listen)
			}
			return migrate.Run(o)
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "只列出要做的事，不改动任何文件")
	cmd.Flags().StringVar(&from, "from", "", "旧版本生成的 .env 在哪个目录（或者就是那个文件），默认是当前目录")
	return cmd
}

// registrations are what the OS starts that migrate points at the new
// places; tests, which must not touch the real ones, replace it.
var registrations = func() []migrate.Registration { return []migrate.Registration{autostartRegistration()} }

// runningDaemon reports whether this user's conch daemon answers, which
// may be using the files to move, and where it listens.
func runningDaemon(ctx context.Context) (string, bool) {
	settings, _, err := clientSettings()
	if err != nil {
		settings = auth.Settings{Listen: auth.DefaultListen}
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, err = api.NewClient(settings).Status(ctx)
	var apiErr *api.APIError
	if err != nil && !errors.As(err, &apiErr) {
		return "", false // nothing, or not conch
	}
	// The system service answers there too, but keeps its files elsewhere.
	if _, err := service.Status(service.Options{Layout: service.SystemLayout(), Run: service.Exec}); err == nil {
		return "", false
	}
	return settings.Listen, true
}

func stopDaemonHint(listen string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "conch daemon 正在运行（%s），它在用要移动的文件。先停掉它再迁移：在终端里运行的按 Ctrl+C；", listen)
	switch runtime.GOOS {
	case "linux":
		b.WriteString("登录时自动启动的运行 systemctl --user stop conch，迁移完再 systemctl --user start conch")
	case "darwin":
		b.WriteString("登录时自动启动的运行 launchctl bootout gui/$(id -u)/" + service.LaunchdUser + "，迁移完再 conch autostart on")
	case "windows":
		b.WriteString("登录时自动启动的在任务管理器里结束 conch.exe，迁移完再 conch autostart on")
	}
	return b.String()
}

// autostartRegistration points autostart at login at the profile's and
// the log's new places. Where the OS keeps it stays: the systemd user
// unit, the launch agent, the Run key.
func autostartRegistration() migrate.Registration {
	return migrate.Registration{Name: "登录时自动启动", Rewrite: func(moved func(string) string, dryRun bool) (string, error) {
		a, err := autostartPlaces(io.Discard)
		if err != nil {
			return "", nil // as root: there is no autostart of this user's
		}
		r, err := service.ReadAutostart(a)
		if errors.Is(err, service.ErrAutostartOff) {
			return "", nil
		}
		if err != nil {
			return "", err
		}
		profile, log := r.Profile(), r.LogFile
		newProfile, newLog := moved(profile), moved(log)
		if e := paths.System(); runtime.GOOS == "darwin" && isOldDaemonLog(e, log) {
			newLog = e.NewDaemonLog()
		}
		if profile == "" || newProfile == profile && newLog == log {
			return "", nil
		}
		var changes []string
		if newProfile != profile {
			changes = append(changes, fmt.Sprintf("profile %s → %s", profile, newProfile))
		}
		if newLog != log {
			changes = append(changes, fmt.Sprintf("日志 %s → %s", log, newLog))
		}
		desc := r.Where + "：" + strings.Join(changes, "，")
		if dryRun {
			return desc, nil
		}
		if err := service.RewriteAutostart(r.Autostart(a, newProfile, newLog), r); err != nil {
			return "", err
		}
		switch runtime.GOOS {
		case "darwin", "windows":
			desc += "（下次登录时生效；现在就启动可以运行 conch autostart on）"
		default:
			desc += "（下次启动时生效）"
		}
		return desc, nil
	}}
}

func isOldDaemonLog(e paths.Env, log string) bool {
	it, _ := paths.ItemNamed("daemon.log")
	for _, p := range e.Legacy(it) {
		if log != "" && e.Same(p, log) {
			return true
		}
	}
	return false
}
