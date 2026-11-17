//go:build !lite

package main

import (
	"io"

	"github.com/spf13/cobra"

	"github.com/xiongnemo/conch/internal/paths"
	"github.com/xiongnemo/conch/internal/tui"
)

func newTUICmd() *cobra.Command {
	return &cobra.Command{
		Use:   "tui",
		Short: "在终端里查看和管理正在运行的 daemon",
		Long:  "在终端里查看和管理正在运行的 daemon。密码从和 daemon 相同的 .env 里读取。",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c := daemonClient()
			// What is still at an old place was said by now; nothing may
			// write over the screen the TUI takes.
			paths.SetNotices(io.Discard)
			return tui.Run(cmd.Context(), c)
		},
	}
}
