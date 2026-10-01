//go:build !lite

package main

import (
	"github.com/spf13/cobra"

	"nautilus/internal/tui"
)

func newTUICmd() *cobra.Command {
	return &cobra.Command{
		Use:   "tui",
		Short: "在终端里查看和管理正在运行的 daemon",
		Long:  "在终端里查看和管理正在运行的 daemon。密码从和 daemon 相同的 .env 里读取。",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return tui.Run(cmd.Context(), daemonClient())
		},
	}
}
