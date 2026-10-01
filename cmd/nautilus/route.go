package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"nautilus/internal/compile"
	"nautilus/internal/explain"
	"nautilus/internal/lists"
	"nautilus/internal/route"
)

func newRouteCmd() *cobra.Command {
	var pl pipeline
	cmd := &cobra.Command{Use: "route", Short: "查看路由表，查询某个地址会怎么走"}
	cmd.PersistentFlags().StringVarP(&pl.profilePath, "profile", "p", "profile.yaml", "profile 文件")
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
			pl.log = cmd.ErrOrStderr()
			res, diags, err := pl.compile(cmd.Context())
			if err != nil {
				return err
			}
			if diags.HasErrors() {
				printDiags(cmd.ErrOrStderr(), diags)
				return errReported
			}
			q := parseQuery(args[0])
			q.Process = process
			e := &explain.Explainer{Result: res, Xray: backendName == "xray", Lists: plainLoader(cmd.Context(), &pl)}
			if !noResolve {
				e.Resolve = func(host string) ([]netip.Addr, error) {
					return net.DefaultResolver.LookupNetIP(cmd.Context(), "ip", host)
				}
			}
			printExplanation(cmd.OutOrStdout(), res, q, e.Explain(q))
			return nil
		},
	}
	get.Flags().StringVar(&backendName, "backend", "mihomo", "按哪个内核的匹配规则来解释：mihomo 或 xray")
	get.Flags().StringVar(&process, "app", "", "发起连接的应用（进程名或路径）")
	get.Flags().BoolVar(&noResolve, "no-resolve", false, "不在本机解析域名")

	list := &cobra.Command{
		Use:   "list",
		Short: "按层显示路由表",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			pl.log = cmd.ErrOrStderr()
			res, diags, err := pl.compile(cmd.Context())
			if err != nil {
				return err
			}
			printDiags(cmd.ErrOrStderr(), diags)
			if diags.HasErrors() {
				return errReported
			}
			printTable(cmd.OutOrStdout(), res)
			return nil
		},
	}
	cmd.AddCommand(get, list)
	return cmd
}

func plainLoader(ctx context.Context, pl *pipeline) func(route.Provider) ([]lists.Entry, error) {
	load := pl.listLoader(ctx)
	return func(p route.Provider) ([]lists.Entry, error) {
		entries, _, err := load(p)
		return entries, err
	}
}

// parseQuery accepts a host, an IP, host:port or a URL.
func parseQuery(arg string) explain.Query {
	q := explain.Query{Host: arg}
	if u, err := url.Parse(arg); err == nil && u.Host != "" {
		q.Host = u.Hostname()
		if p, err := strconv.Atoi(u.Port()); err == nil {
			q.Port = p
		} else if u.Scheme == "https" {
			q.Port = 443
		} else if u.Scheme == "http" {
			q.Port = 80
		}
		return q
	}
	if h, p, err := net.SplitHostPort(arg); err == nil {
		q.Host = h
		q.Port, _ = strconv.Atoi(p)
	}
	return q
}

func printExplanation(w io.Writer, res *compile.Result, q explain.Query, ex *explain.Explanation) {
	fmt.Fprintf(w, "%s → %s\n", q.Host, ex.Target)
	switch {
	case ex.Matched != nil:
		fmt.Fprintf(w, "  命中：%s\n", describeRule(ex.Matched.Rule))
	case res.Settings.Mode != "rule":
		fmt.Fprintf(w, "  当前是 %s 模式，所有流量都走 %s\n", res.Settings.Mode, ex.Target)
	default:
		fmt.Fprintln(w, "  没有规则命中，走默认出口")
	}
	if len(ex.Resolved) > 0 {
		fmt.Fprintf(w, "  （本机解析为 %s 后按 IP 匹配）\n", ex.Resolved[0])
	}
	fmt.Fprintf(w, "  出口：%s\n", describeOutbound(res, ex.Target))
	if len(ex.Shadowed) > 0 {
		fmt.Fprintln(w, "  也匹配，但被压过了：")
		for _, h := range ex.Shadowed {
			fmt.Fprintf(w, "    - %s → %s\n", describeRule(h.Rule), h.Rule.Target)
		}
	}
	if uncertain := ex.Relevant(); len(uncertain) > 0 {
		fmt.Fprintln(w, "  排在前面、要等到运行时才能确定的规则（如果命中，结果会不同）：")
		for _, h := range uncertain {
			fmt.Fprintf(w, "    - %s → %s（%s）\n", describeRule(h.Rule), h.Rule.Target, cmpNote(h.Note))
		}
	}
}

func cmpNote(n string) string {
	if n == "" {
		return "需要运行时判断"
	}
	return n
}

func describeRule(r route.Rule) string {
	o := r.Origin
	where := ""
	if s := o.Pos.String(); s != "" {
		where = "（" + s + "）"
	}
	switch {
	case o.Builtin:
		return "内置的 lan 条目（局域网和本机地址）"
	case o.Imported && o.Tier == route.TierDefault:
		return "订阅规则里的 MATCH（没有设置 routes.default）"
	case o.Imported:
		return fmt.Sprintf("订阅 %s 的规则 %s", o.Key, ruleText(r))
	}
	switch o.Tier {
	case route.TierApp:
		return "应用条目 " + o.Key + where
	case route.TierDomain:
		return "手动条目 " + o.Key + where
	case route.TierIP:
		return "IP 条目 " + o.Key + where
	case route.TierList:
		return "规则列表 " + o.Key + where
	default:
		return "默认出口" + where
	}
}

// ruleText renders an imported rule compactly.
func ruleText(r route.Rule) string {
	if r.Match == route.MatchRaw {
		return r.Value
	}
	return [...]string{"进程路径", "进程", "域名", "域名后缀", "关键词", "IP", "规则集", "端口", "网络", "", ""}[r.Match] + " " + r.Value
}

func describeOutbound(res *compile.Result, name string) string {
	switch name {
	case "DIRECT":
		return "直连"
	case "REJECT", "REJECT-DROP":
		return "屏蔽"
	case compile.GlobalGroup:
		return "全局出口组 GLOBAL"
	}
	for _, c := range res.Chains {
		if c.Name == name {
			hops := slices.Clone(c.Path)
			hops[0] = describeHop(res, hops[0])
			return "链 " + name + "：" + strings.Join(hops, " → ")
		}
	}
	for _, g := range res.Groups {
		if g.Name == name {
			return describeGroup(g)
		}
	}
	for _, p := range res.Proxies {
		if p.Name == name && p.Kind == compile.ProxyNode {
			return fmt.Sprintf("节点 %s（%s，%s）", name, p.Node.View.Type, net.JoinHostPort(p.Node.View.Server, strconv.Itoa(p.Node.View.Port)))
		}
	}
	return name
}

func describeHop(res *compile.Result, name string) string {
	for _, g := range res.Groups {
		if g.Name == name {
			return name + "（" + groupKind(g.Type) + "）"
		}
	}
	return name
}

func describeGroup(g *compile.Group) string {
	s := fmt.Sprintf("出口组 %s（%s，%d 个成员", g.Name, groupKind(g.Type), len(g.Members))
	if g.Type == "select" && len(g.Members) > 0 {
		s += "，默认选中 " + g.Members[0]
	}
	return s + "）"
}

func groupKind(t string) string {
	switch t {
	case "select":
		return "手动选择"
	case "url-test":
		return "自动最快"
	case "fallback":
		return "故障转移"
	case "load-balance":
		return "负载均衡"
	}
	return t
}

// printTable shows the routing table by tier. Domain entries are drawn as
// a tree so a more specific entry appears under the one it overrides.
func printTable(w io.Writer, res *compile.Result) {
	var apps, domains, ips, lists []route.Rule
	var def *route.Rule
	builtin := 0
	for i, r := range res.Rules {
		switch {
		case r.Origin.Builtin:
			builtin++
		case r.Match == route.MatchFinal:
			def = &res.Rules[i]
		case r.Origin.Tier == route.TierApp:
			apps = append(apps, r)
		case r.Origin.Tier == route.TierDomain:
			domains = append(domains, r)
		case r.Origin.Tier == route.TierIP:
			ips = append(ips, r)
		default:
			lists = append(lists, r)
		}
	}
	section := func(title string, rules []route.Rule, line func(route.Rule) string) {
		if len(rules) == 0 {
			return
		}
		fmt.Fprintln(w, title)
		for _, r := range rules {
			fmt.Fprintln(w, "  "+line(r))
		}
	}
	section("应用条目", apps, func(r route.Rule) string { return r.Origin.Key + " → " + r.Target })
	if len(domains) > 0 {
		fmt.Fprintln(w, "手动条目（越具体越优先，与书写顺序无关）")
		for _, l := range domainTree(domains) {
			fmt.Fprintln(w, "  "+l)
		}
	}
	section("IP 条目（前缀越长越优先）", ips, func(r route.Rule) string {
		s := r.Origin.Key + " → " + r.Target
		if !r.NoResolve {
			s += "（也匹配解析后的域名）"
		}
		return s
	})
	if len(lists) > 0 {
		fmt.Fprintln(w, "规则列表（从上到下）")
		n, last := 0, ""
		for i := 0; i < len(lists); i++ {
			r := lists[i]
			if r.Origin.Imported {
				if r.Origin.Key == last {
					continue
				}
				count := 0
				for _, x := range lists[i:] {
					if x.Origin.Imported && x.Origin.Key == r.Origin.Key {
						count++
					}
				}
				n++
				last = r.Origin.Key
				fmt.Fprintf(w, "  %d. 订阅 %s 自带的规则（%d 条）\n", n, r.Origin.Key, count)
				continue
			}
			n++
			last = ""
			fmt.Fprintf(w, "  %d. %s → %s\n", n, r.Origin.Key, r.Target)
		}
	}
	if def != nil {
		fmt.Fprintf(w, "默认出口 → %s\n", def.Target)
	}
	if builtin > 0 {
		fmt.Fprintf(w, "（另有内置的 lan 条目 %d 条：局域网和本机地址走直连；写 lan: off 可关闭）\n", builtin)
	}
}

func domainTree(rules []route.Rule) []string {
	type node struct {
		r   route.Rule
		key string // reversed labels, so parents sort before children
	}
	var nodes []node
	for _, r := range rules {
		labels := strings.Split(r.Value, ".")
		slices.Reverse(labels)
		nodes = append(nodes, node{r, strings.Join(labels, ".")})
	}
	slices.SortStableFunc(nodes, func(a, b node) int { return strings.Compare(a.key, b.key) })
	var out []string
	for i, n := range nodes {
		depth := 0
		for _, p := range nodes[:i] {
			if p.r.Match == route.MatchDomainSuffix && (n.key == p.key || strings.HasPrefix(n.key, p.key+".")) {
				depth++
			}
		}
		out = append(out, strings.Repeat("  ", depth)+n.r.Origin.Key+" → "+n.r.Target)
	}
	return out
}
