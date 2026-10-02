package main

import (
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

func newPairCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pair",
		Short: "获取配对码，让浏览器扩展连接 daemon",
		Long: `获取一个 6 位配对码，在 conch 浏览器扩展里输入，扩展就能查询和修改路由。
配对码只能用一次，2 分钟内有效。扩展只能查看和修改路由，不能改模式、系统代理或重启内核。`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			code, expires, err := daemonClient().PairCode(cmd.Context())
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "配对码：%s\n\n在浏览器扩展里输入这个配对码，%s 前有效（只能用一次）。\n", code, expires.Local().Format("15:04:05"))
			return nil
		},
	}
	list := &cobra.Command{
		Use:   "list",
		Short: "列出已配对的浏览器扩展",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			list, err := daemonClient().Pairings(cmd.Context())
			if err != nil {
				return err
			}
			if len(list) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "还没有配对的浏览器扩展")
				return nil
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ID\t名字\t来源\t配对时间")
			for _, p := range list {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", p.ID, p.Name, p.Origin, p.Created.Local().Format(time.DateTime))
			}
			return w.Flush()
		},
	}
	revoke := &cobra.Command{
		Use:   "revoke <ID>",
		Short: "取消一个浏览器扩展的配对",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := daemonClient().RevokePairing(cmd.Context(), args[0]); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "已取消配对，这个扩展需要重新配对才能使用")
			return nil
		},
	}
	cmd.AddCommand(list, revoke)
	return cmd
}
