package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/xiongnemo/conch/internal/api"
	"github.com/xiongnemo/conch/internal/compile"
	"github.com/xiongnemo/conch/internal/daemon"
	"github.com/xiongnemo/conch/internal/explain"
	"github.com/xiongnemo/conch/internal/lists"
	"github.com/xiongnemo/conch/internal/route"
	"github.com/xiongnemo/conch/internal/view"
)

func newRouteCmd() *cobra.Command {
	var pl pipeline
	cmd := &cobra.Command{Use: "route", Short: "查看路由表，查询某个地址会怎么走"}
	cmd.PersistentFlags().StringVarP(&pl.profilePath, "profile", "p", "", "profile 文件（默认是当前目录或配置目录里的 profile.yaml）")
	cmd.PersistentFlags().BoolVar(&pl.offline, "offline", false, "不下载订阅和规则列表，只用已缓存的")

	var (
		backendName string
		process     string
		noResolve   bool
	)
	get := &cobra.Command{
		Use:   "get <域名|IP|URL>",
		Short: "这个地址会怎么走？为什么？",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := lookupBackend(backendName); err != nil {
				return err
			}
			q := explain.ParseQuery(args[0])
			q.Process = process
			// The running daemon knows the temporary entries and its kernel.
			if askDaemon(cmd, "backend", "no-resolve") {
				v, err := daemonClient().Explain(cmd.Context(), args[0], process)
				if !errors.Is(err, api.ErrNotRunning) {
					if err != nil {
						return err
					}
					printExplanation(cmd.OutOrStdout(), q.Host, v)
					return nil
				}
			}
			if err := pl.resolve(); err != nil {
				return err
			}
			pl.log = cmd.ErrOrStderr()
			res, diags, err := pl.compile(cmd.Context())
			if err != nil {
				return err
			}
			if diags.HasErrors() {
				printDiags(cmd.ErrOrStderr(), diags)
				return errReported
			}
			e := &explain.Explainer{Result: res, Xray: backendName == "xray", Lists: plainLoader(cmd.Context(), &pl)}
			if !noResolve {
				e.Resolve = func(host string) ([]netip.Addr, error) {
					return net.DefaultResolver.LookupNetIP(cmd.Context(), "ip", host)
				}
			}
			printExplanation(cmd.OutOrStdout(), q.Host, view.Explain(res, e.Explain(q)))
			return nil
		},
	}
	get.Flags().StringVar(&backendName, "backend", "mihomo", "按哪个内核的匹配规则来解释：mihomo、xray 或 sing-box")
	get.Flags().StringVar(&process, "app", "", "发起连接的应用（进程名或路径）")
	get.Flags().BoolVar(&noResolve, "no-resolve", false, "不在本机解析域名")

	list := &cobra.Command{
		Use:   "list",
		Short: "按层显示路由表",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if askDaemon(cmd) {
				t, err := daemonClient().Routes(cmd.Context())
				if !errors.Is(err, api.ErrNotRunning) {
					if err != nil {
						return err
					}
					printTable(cmd.OutOrStdout(), t)
					return nil
				}
			}
			if err := pl.resolve(); err != nil {
				return err
			}
			pl.log = cmd.ErrOrStderr()
			res, diags, err := pl.compile(cmd.Context())
			if err != nil {
				return err
			}
			printDiags(cmd.ErrOrStderr(), diags)
			if diags.HasErrors() {
				return errReported
			}
			printTable(cmd.OutOrStdout(), view.TableOf(res, nil, ""))
			return nil
		},
	}
	var forText string
	add := &cobra.Command{
		Use:   "add <目标> <出口>",
		Short: "添加条目，例如 conch route add openai.com AI-Exit --for 2h",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			target, via := args[0], args[1]
			ttl, err := parseFor(forText)
			if err != nil {
				return err
			}
			err = daemonClient().SetRoute(cmd.Context(), target, via, ttl)
			if errors.Is(err, api.ErrNotRunning) {
				if ttl > 0 {
					return errors.New("临时条目需要 conch daemon 正在运行")
				}
				err = addOffline(cmd, &pl, target, via)
			}
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "已添加：%s → %s\n", target, via)
			return nil
		},
	}
	add.Flags().StringVar(&forText, "for", "", "临时条目的有效时长，例如 30m、2h，到期自动删除；run 表示到 conch 停止为止")
	del := &cobra.Command{
		Use:   "del <目标>",
		Short: "删除通过 conch 添加的条目（包括临时条目）",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			err := daemonClient().DeleteRoute(cmd.Context(), args[0])
			if errors.Is(err, api.ErrNotRunning) {
				profile, perr := resolveProfile(pl.profilePath)
				if perr != nil {
					return perr
				}
				err = daemon.RemoveManagedRoute(profile, args[0])
			}
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "已删除：%s\n", args[0])
			return nil
		},
	}
	cmd.AddCommand(get, list, add, del)
	return cmd
}

// askDaemon reports whether to answer from the running daemon: unless
// the command was pointed at a profile, told to stay offline, or given one
// of the extra flags only the offline answer honours.
func askDaemon(cmd *cobra.Command, offlineFlags ...string) bool {
	for _, f := range append([]string{"profile", "offline"}, offlineFlags...) {
		if cmd.Flags().Changed(f) {
			return false
		}
	}
	return true
}

func daemonClient() *api.Client {
	settings, _, _ := clientSettings()
	return api.NewClient(settings)
}

// addOffline writes a route to managed.yaml when no daemon runs, after
// checking that the outbound exists in the compiled profile.
func addOffline(cmd *cobra.Command, pl *pipeline, target, via string) error {
	profile, err := resolveProfile(pl.profilePath)
	if err != nil {
		return err
	}
	check := *pl
	check.profilePath, check.log = profile, cmd.ErrOrStderr()
	res, _, err := check.compile(cmd.Context())
	if err != nil {
		return err
	}
	if !hasOutbound(res, via) {
		return fmt.Errorf("找不到出口 %q", via)
	}
	if err := daemon.AddManagedRoute(profile, target, via); err != nil {
		return err
	}
	fmt.Fprintln(cmd.ErrOrStderr(), "daemon 没有在运行：条目已写入 managed.yaml，下次启动时生效")
	return nil
}

func hasOutbound(res *compile.Result, name string) bool {
	if name == "DIRECT" || name == "REJECT" || name == "REJECT-DROP" {
		return true
	}
	for _, g := range res.Groups {
		if g.Name == name {
			return true
		}
	}
	for _, c := range res.Chains {
		if c.Name == name {
			return true
		}
	}
	for _, p := range res.Proxies {
		if p.Name == name && p.Kind == compile.ProxyNode {
			return true
		}
	}
	return false
}

func plainLoader(ctx context.Context, pl *pipeline) func(route.Provider) ([]lists.Entry, error) {
	load := pl.listLoader(ctx)
	return func(p route.Provider) ([]lists.Entry, error) {
		entries, _, err := load(p)
		return entries, err
	}
}

func printExplanation(w io.Writer, host string, v view.Explanation) {
	fmt.Fprintf(w, "%s → %s\n", host, v.Target)
	fmt.Fprintf(w, "  命中：%s\n", v.Matched)
	if v.Resolved != "" {
		fmt.Fprintf(w, "  （本机解析为 %s 后按 IP 匹配）\n", v.Resolved)
	}
	fmt.Fprintf(w, "  出口：%s\n", v.Outbound)
	if len(v.Shadowed) > 0 {
		fmt.Fprintln(w, "  也匹配，但被压过了：")
		for _, s := range v.Shadowed {
			fmt.Fprintln(w, "    - "+s)
		}
	}
	if len(v.Uncertain) > 0 {
		fmt.Fprintln(w, "  排在前面、要等到运行时才能确定的规则（如果命中，结果会不同）：")
		for _, s := range v.Uncertain {
			fmt.Fprintln(w, "    - "+s)
		}
	}
}

// printTable shows the routing table by tier, domain entries as a tree.
func printTable(w io.Writer, t view.Table) {
	if len(t.Apps) > 0 {
		fmt.Fprintln(w, "应用条目")
		for _, e := range t.Apps {
			fmt.Fprintf(w, "  %s → %s%s\n", e.Target, e.Via, suffix(e))
		}
	}
	if len(t.Domains) > 0 {
		fmt.Fprintln(w, "手动条目（越具体越优先，与书写顺序无关）")
		for _, e := range t.Domains {
			fmt.Fprintf(w, "  %s%s → %s%s\n", strings.Repeat("  ", e.Depth), e.Target, e.Via, suffix(e))
		}
	}
	if len(t.IPs) > 0 {
		fmt.Fprintln(w, "IP 条目（前缀越长越优先）")
		for _, e := range t.IPs {
			s := suffix(e)
			if e.Resolve {
				s = "（也匹配解析后的域名）" + s
			}
			fmt.Fprintf(w, "  %s → %s%s\n", e.Target, e.Via, s)
		}
	}
	if len(t.Lists) > 0 {
		fmt.Fprintln(w, "规则列表（从上到下）")
		for i, l := range t.Lists {
			if l.Subscription {
				fmt.Fprintf(w, "  %d. 订阅 %s 自带的规则（%d 条）\n", i+1, l.Name, l.Rules)
			} else {
				fmt.Fprintf(w, "  %d. %s → %s\n", i+1, l.Name, l.Via)
			}
		}
	}
	if t.Default != "" {
		fmt.Fprintf(w, "默认出口 → %s\n", t.Default)
	}
	if t.Builtins > 0 {
		fmt.Fprintf(w, "（另有内置的 lan 条目 %d 条：局域网和本机地址走直连；写 lan: off 可关闭）\n", t.Builtins)
	}
}

// parseFor reads --for: a duration, or run (until conch stops).
func parseFor(s string) (time.Duration, error) {
	switch s {
	case "":
		return 0, nil
	case "run":
		return daemon.ForRun, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("--for 应该写成 30m、2h 这样的时长，或者 run")
	}
	return d, nil
}

func suffix(e view.Entry) string {
	if e.ForRun {
		return "（临时，本次运行）"
	}
	if e.Expires != nil {
		return "（临时，到 " + e.Expires.Local().Format("15:04") + "）"
	}
	return ""
}
