// Package view turns compiled profiles and explanations into what users
// read: the routing table by tier and plain-language descriptions. The
// CLI, the API (and through it the Web UI and TUI) share it.
package view

import (
	"fmt"
	"net"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/xiongnemo/conch/internal/compile"
	"github.com/xiongnemo/conch/internal/explain"
	"github.com/xiongnemo/conch/internal/route"
)

// Entry is one manual route.
type Entry struct {
	Target    string     `json:"target"`
	Via       string     `json:"via"`
	Source    string     `json:"source,omitempty"` // file:line
	Depth     int        `json:"depth,omitempty"`  // nesting in the domain tree
	Resolve   bool       `json:"resolve,omitempty"`
	Expires   *time.Time `json:"expires,omitempty"`
	ForRun    bool       `json:"forRun,omitempty"`  // temporary until conch stops
	Managed   bool       `json:"managed,omitempty"` // editable through conch
	Generated bool       `json:"generated,omitempty"`
}

// temporary marks a temporary entry: until expires[key], or for the run
// when that is the zero time.
func (e *Entry) temporary(expires map[string]time.Time, key string) {
	if exp, ok := expires[key]; ok {
		if exp.IsZero() {
			e.ForRun = true
		} else {
			e.Expires = &exp
		}
	}
}

// List is one rule list, or a subscription's own rules.
type List struct {
	Name         string `json:"name"`
	Via          string `json:"via,omitempty"` // empty for subscription rules
	Subscription bool   `json:"subscription,omitempty"`
	Rules        int    `json:"rules"`
	Source       string `json:"source,omitempty"`
}

// Table is the routing table in reading order.
type Table struct {
	Apps     []Entry `json:"apps"`
	Domains  []Entry `json:"domains"`
	IPs      []Entry `json:"ips"`
	Lists    []List  `json:"lists"`
	Default  string  `json:"default"`
	Builtins int     `json:"builtins"` // rules from the built-in lan entry
}

// TableOf builds the routing table. expires maps temporary targets to
// their expiry; managedFile is the daemon-owned file.
func TableOf(res *compile.Result, expires map[string]time.Time, managedFile string) Table {
	var t Table
	var domains []route.Rule
	for _, r := range res.Rules {
		o := r.Origin
		switch {
		case o.Builtin:
			t.Builtins++
			continue
		case r.Match == route.MatchFinal:
			t.Default = r.Target
			continue
		}
		e := Entry{Target: o.Key, Via: r.Target, Source: o.Pos.String(), Resolve: r.Match == route.MatchIPCIDR && !r.NoResolve}
		e.temporary(expires, o.Key)
		e.Managed = e.Expires != nil || e.ForRun || (managedFile != "" && o.Pos.File == managedFile)
		switch o.Tier {
		case route.TierApp:
			t.Apps = append(t.Apps, e)
		case route.TierDomain:
			domains = append(domains, r)
		case route.TierIP:
			t.IPs = append(t.IPs, e)
		default:
			if o.Imported {
				if n := len(t.Lists); n > 0 && t.Lists[n-1].Subscription && t.Lists[n-1].Name == o.Key {
					t.Lists[n-1].Rules++
					continue
				}
				t.Lists = append(t.Lists, List{Name: o.Key, Subscription: true, Rules: 1, Source: o.Pos.String()})
				continue
			}
			t.Lists = append(t.Lists, List{Name: o.Key, Via: r.Target, Rules: 1, Source: o.Pos.String()})
		}
	}
	t.Domains = domainTree(domains, expires, managedFile)
	return t
}

// domainTree orders domain entries so that an entry appears right under
// the less specific entry it overrides.
func domainTree(rules []route.Rule, expires map[string]time.Time, managedFile string) []Entry {
	type node struct {
		r   route.Rule
		key string // reversed labels: parents sort before children
	}
	var nodes []node
	for _, r := range rules {
		labels := strings.Split(r.Value, ".")
		slices.Reverse(labels)
		nodes = append(nodes, node{r, strings.Join(labels, ".")})
	}
	slices.SortStableFunc(nodes, func(a, b node) int { return strings.Compare(a.key, b.key) })
	var out []Entry
	for i, n := range nodes {
		depth := 0
		for _, p := range nodes[:i] {
			if p.r.Match == route.MatchDomainSuffix && (n.key == p.key || strings.HasPrefix(n.key, p.key+".")) {
				depth++
			}
		}
		o := n.r.Origin
		e := Entry{Target: o.Key, Via: n.r.Target, Source: o.Pos.String(), Depth: depth}
		e.temporary(expires, o.Key)
		e.Managed = e.Expires != nil || e.ForRun || (managedFile != "" && o.Pos.File == managedFile)
		out = append(out, e)
	}
	return out
}

// Explanation is an explain result in words.
type Explanation struct {
	Target   string   `json:"target"`
	Outbound string   `json:"outbound"`           // where it goes, described
	Matched  string   `json:"matched"`            // why
	Resolved string   `json:"resolved,omitempty"` // the IP used for matching
	Shadowed []string `json:"shadowed,omitempty"`
	// Uncertain are earlier rules that cannot be decided here and would
	// send the connection elsewhere: with any, Target is only likely.
	Uncertain []string `json:"uncertain,omitempty"`
	// Apps are earlier rules for connections from particular apps, which
	// would send those elsewhere.
	Apps []string `json:"apps,omitempty"`
}

func Explain(res *compile.Result, ex *explain.Explanation) Explanation {
	v := Explanation{Target: ex.Target, Outbound: Outbound(res, ex.Target)}
	switch {
	case ex.Matched != nil:
		v.Matched = Rule(ex.Matched.Rule)
	case res.Settings.Mode != "rule":
		v.Matched = fmt.Sprintf("当前是 %s 模式，所有流量都走 %s", res.Settings.Mode, ex.Target)
	default:
		v.Matched = "没有规则命中，走默认出口"
	}
	if len(ex.Resolved) > 0 {
		v.Resolved = ex.Resolved[0].String()
	}
	for _, h := range ex.Shadowed {
		// Subscriptions often repeat a rule; once is enough, and not again
		// after the rule that won.
		line := Rule(h.Rule) + " → " + h.Rule.Target
		if ex.Matched != nil && line == v.Matched+" → "+ex.Matched.Rule.Target {
			continue
		}
		if !slices.Contains(v.Shadowed, line) {
			v.Shadowed = append(v.Shadowed, line)
		}
	}
	// A subscription's app rules (often phone app ids) take one line per
	// exit; the rest one line each.
	type apps struct {
		at    int
		names []string
	}
	grouped := map[[2]string]*apps{}
	for _, h := range ex.Relevant() {
		r := h.Rule
		if r.Match == route.MatchProcessName || r.Match == route.MatchProcessPath {
			if !r.Origin.Imported {
				v.Apps = append(v.Apps, Rule(r)+" → "+r.Target)
				continue
			}
			k := [2]string{r.Origin.Key, r.Target}
			if grouped[k] == nil {
				grouped[k] = &apps{at: len(v.Apps)}
				v.Apps = append(v.Apps, "")
			}
			grouped[k].names = append(grouped[k].names, r.Value)
			v.Apps[grouped[k].at] = appRules(k[0], k[1], grouped[k].names)
			continue
		}
		note := h.Note
		if note == "" {
			note = "需要运行时判断"
		}
		v.Uncertain = append(v.Uncertain, fmt.Sprintf("%s → %s（%s）", Rule(r), r.Target, note))
	}
	return v
}

// appRules describes a subscription's app rules that go to one exit.
func appRules(sub, target string, names []string) string {
	if len(names) == 1 {
		return fmt.Sprintf("订阅 %s 的规则 进程 %s → %s", sub, names[0], target)
	}
	shown := strings.Join(names[:min(len(names), 2)], "、")
	if len(names) > 2 {
		shown += " 等"
	}
	return fmt.Sprintf("订阅 %s 的 %d 条按应用的规则（%s）→ %s", sub, len(names), shown, target)
}

// Rule names the entry, list or subscription rule a compiled rule came from.
func Rule(r route.Rule) string {
	o := r.Origin
	where := ""
	pos := o.Pos
	pos.File = filepath.Base(pos.File) // profile.yaml:3 is enough to find it
	if pos.File == "." {
		pos.File = ""
	}
	if s := pos.String(); s != "" {
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

func ruleText(r route.Rule) string {
	if r.Match == route.MatchRaw {
		return r.Value
	}
	return [...]string{"进程路径", "进程", "域名", "域名后缀", "关键词", "IP", "规则集", "端口", "网络", "", ""}[r.Match] + " " + r.Value
}

// Outbound describes an outbound in a phrase.
func Outbound(res *compile.Result, name string) string {
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
			hops[0] = hop(res, hops[0])
			return "链 " + name + "：" + strings.Join(hops, " → ")
		}
	}
	for _, g := range res.Groups {
		if g.Name == name {
			s := fmt.Sprintf("出口组 %s（%s，%d 个成员", g.Name, GroupKind(g.Type), len(g.Members))
			if g.Type == "select" {
				s += "，当前选中 " + cmpOr(g.Selected, firstOf(g.Members))
			}
			return s + "）"
		}
	}
	for _, p := range res.Proxies {
		if p.Name == name && p.Kind == compile.ProxyNode {
			return fmt.Sprintf("节点 %s（%s，%s）", name, p.Node.View.Type, net.JoinHostPort(p.Node.View.Server, strconv.Itoa(p.Node.View.Port)))
		}
	}
	return name
}

func hop(res *compile.Result, name string) string {
	for _, g := range res.Groups {
		if g.Name == name {
			return name + "（" + GroupKind(g.Type) + "）"
		}
	}
	return name
}

// GroupKind names a group type the way the UI does.
func GroupKind(t string) string {
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

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func firstOf(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}
