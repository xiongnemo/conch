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

func newGroupCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "group", Short: "添加、修改或删除出口组（需要 daemon 在运行，写在 managed.yaml）"}
	types := map[string]string{"手动选择": "select", "自动最快": "url-test", "故障转移": "fallback", "负载均衡": "load-balance"}
	cmd.AddCommand(&cobra.Command{
		Use:   "add <组名> <类型> <成员> [更多成员……]",
		Short: "添加或修改一个出口组；类型是 select（手动选择）、url-test（自动最快）、fallback（故障转移）或 load-balance（负载均衡）",
		Example: "  conch group add 美国 url-test US-01 US-02 US-03\n" +
			"  conch group add AI 手动选择 美国 日本 DIRECT",
		Args: cobra.MinimumNArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			typ := cmpOr(types[args[1]], args[1])
			if err := daemonClient().SetGroup(cmd.Context(), args[0], typ, args[2:]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "已保存出口组 %s\n", args[0])
			return nil
		},
	}, &cobra.Command{
		Use:   "del <组名>",
		Short: "删除用 conch 添加的出口组",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := daemonClient().DeleteGroup(cmd.Context(), args[0]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "已删除出口组 %s\n", args[0])
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
