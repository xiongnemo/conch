//go:build lite

package main

import (
	"errors"

	"github.com/spf13/cobra"
)

// The lite build for routers has no TUI; the Web UI does the same job.
func newTUICmd() *cobra.Command {
	return &cobra.Command{
		Use:    "tui",
		Short:  "（精简版没有 TUI，请用 Web UI）",
		Hidden: true,
		RunE: func(*cobra.Command, []string) error {
			return errors.New("这是给路由器用的精简版，没有 TUI；请在浏览器里打开 Web UI")
		},
	}
}
