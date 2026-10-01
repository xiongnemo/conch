package main

import (
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"

	"nautilus/internal/model"
	"nautilus/internal/paths"
	"nautilus/internal/subscription"
)

func newSubCmd() *cobra.Command {
	var profilePath string
	cmd := &cobra.Command{Use: "sub", Short: "管理订阅"}
	cmd.PersistentFlags().StringVarP(&profilePath, "profile", "p", "profile.yaml", "profile 文件")

	run := func(update bool) func(*cobra.Command, []string) error {
		return func(cmd *cobra.Command, args []string) error {
			p, err := model.Load(profilePath)
			if err != nil {
				return err
			}
			store := &subscription.Store{Dir: paths.SubscriptionsDir(), Offline: !update, Log: cmd.ErrOrStderr()}
			failed := false
			for _, sub := range p.Subscriptions {
				if len(args) > 0 && !slices.Contains(args, sub.Name) {
					continue
				}
				var snap *subscription.Snapshot
				var info *subscription.Info
				if update {
					snap, info, err = store.Update(cmd.Context(), sub)
				} else {
					snap, info, err = store.Load(cmd.Context(), sub)
				}
				if err != nil {
					fmt.Fprintln(cmd.ErrOrStderr(), "错误：", err)
					failed = true
					continue
				}
				printSub(cmd.OutOrStdout(), sub, snap, info)
			}
			if failed {
				return errReported
			}
			return nil
		}
	}
	cmd.AddCommand(
		&cobra.Command{Use: "update [名字…]", Short: "下载订阅（失败时保留原来的缓存）", RunE: run(true)},
		&cobra.Command{Use: "list", Short: "查看已下载的订阅", Args: cobra.NoArgs, RunE: run(false)},
	)
	return cmd
}

func printSub(w io.Writer, sub *model.Subscription, snap *subscription.Snapshot, info *subscription.Info) {
	fmt.Fprintf(w, "%s：%s\n", sub.Name, snap.Summary())
	if info.Total > 0 {
		used := info.Upload + info.Download
		fmt.Fprintf(w, "  流量：已用 %s / 共 %s（剩余 %s）\n", bytesText(used), bytesText(info.Total), bytesText(info.Total-used))
	}
	if info.Expire > 0 {
		exp := time.Unix(info.Expire, 0)
		fmt.Fprintf(w, "  到期：%s（还有 %d 天）\n", exp.Format("2006-01-02"), int(time.Until(exp).Hours()/24))
	}
	if !info.FetchedAt.IsZero() {
		fmt.Fprintf(w, "  更新于：%s\n", info.FetchedAt.Local().Format("2006-01-02 15:04"))
	}
}

func bytesText(n int64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	v := float64(n)
	i := 0
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}

func newImportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "import <分享链接|文件|->…",
		Short: "把分享链接或 Clash 配置里的节点转换成 profile 的写法",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var bodies []string
			for _, a := range args {
				switch {
				case a == "-":
					b, err := io.ReadAll(cmd.InOrStdin())
					if err != nil {
						return err
					}
					bodies = append(bodies, string(b))
				case strings.Contains(a, "://"):
					bodies = append(bodies, a)
				default:
					b, err := os.ReadFile(a)
					if err != nil {
						return err
					}
					bodies = append(bodies, string(b))
				}
			}
			var nodes []*yaml.Node
			for _, b := range bodies {
				snap, err := subscription.Parse([]byte(b), nil)
				if err != nil {
					return err
				}
				for _, w := range snap.Warnings {
					fmt.Fprintln(cmd.ErrOrStderr(), "警告：", w)
				}
				nodes = append(nodes, snap.Nodes...)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "nodes:")
			for _, n := range nodes {
				n.Style = yaml.FlowStyle
				line, err := yaml.Marshal(n)
				if err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "  - %s", line)
			}
			return nil
		},
	}
}
