package main

import (
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/xiongnemo/conch/internal/agent"
	"github.com/xiongnemo/conch/internal/paths"
)

func newAgentCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "agent",
		Short: "在桌面会话里替系统服务设置系统代理（由 conch service install 安装）",
		Long: `系统代理是每个用户自己的设置，以系统服务运行的 daemon 改不了。agent 在用户登录后运行，
按 daemon 的「系统代理」开关设置这个用户的系统代理；daemon 停止或 agent 退出时恢复原来的设置。
自己运行 conch daemon 时不需要 agent。`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			a := &agent.Agent{Client: daemonClient(), StatePath: filepath.Join(paths.DataDir(), "agent.json"), Log: quietAgent(cmd.ErrOrStderr())}
			return a.Run(ctx)
		},
	}
}
