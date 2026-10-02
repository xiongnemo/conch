package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newNodeCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "node", Short: "添加或删除节点（需要 daemon 在运行，写在 managed.yaml）"}
	cmd.AddCommand(&cobra.Command{
		Use:     "add <分享链接>",
		Short:   "用分享链接添加节点（vmess://、vless://、ss://、trojan://、hysteria2://、socks://……）",
		Example: "  conch node add 'vless://uuid@example.com:443?security=reality&…#HK 01'",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name, err := daemonClient().AddNode(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "已添加节点 %s\n", name)
			return nil
		},
	}, &cobra.Command{
		Use:   "del <节点名>",
		Short: "删除用 conch 添加的节点",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := daemonClient().DeleteNode(cmd.Context(), args[0]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "已删除节点 %s\n", args[0])
			return nil
		},
	})
	return cmd
}

func newChainCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "chain", Short: "添加、修改或删除链（需要 daemon 在运行，写在 managed.yaml）"}
	cmd.AddCommand(&cobra.Command{
		Use:     "add <链名> <第一跳> <第二跳> [更多跳……]",
		Short:   "添加或修改一条链：流量从第一跳进去，从最后一跳出来",
		Example: "  conch chain add AI-Exit 香港自动 home",
		Args:    cobra.MinimumNArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := daemonClient().SetChain(cmd.Context(), args[0], args[1:]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "已保存链 %s\n", args[0])
			return nil
		},
	}, &cobra.Command{
		Use:   "del <链名>",
		Short: "删除用 conch 添加的链",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := daemonClient().DeleteChain(cmd.Context(), args[0]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "已删除链 %s\n", args[0])
			return nil
		},
	})
	return cmd
}
