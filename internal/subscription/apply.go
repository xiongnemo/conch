package subscription

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/xiongnemo/conch/internal/compile"
	"github.com/xiongnemo/conch/internal/diag"
	"github.com/xiongnemo/conch/internal/model"
	"github.com/xiongnemo/conch/internal/route"
	"github.com/xiongnemo/conch/internal/rx"
)

var builtins = []string{"DIRECT", "REJECT", "REJECT-DROP", "GLOBAL"}

// Apply merges subscriptions into a profile. Imported names that clash
// with existing ones are prefixed with the subscription's name. Importing
// rules implies importing groups, and groups imply nodes.
func Apply(p *model.Profile, snaps map[string]*Snapshot, d *diag.List) {
	taken := map[string]bool{}
	for _, b := range builtins {
		taken[b] = true
	}
	for _, n := range p.Nodes {
		taken[n.Name] = true
	}
	for _, g := range p.Groups {
		taken[g.Name] = true
	}
	for _, c := range p.Chains {
		taken[c.Name] = true
	}
	for _, sub := range p.Subscriptions {
		snap := snaps[sub.Name]
		if snap == nil {
			continue
		}
		for _, w := range snap.Warnings {
			d.Warnf(sub.Pos, "订阅 %q：%s", sub.Name, w)
		}
		m := &merger{p: p, sub: sub, snap: snap, taken: taken, names: map[string]string{}, d: d}
		m.nodes()
		if sub.Imports("groups") || sub.Imports("rules") {
			m.groups()
		}
		if sub.Imports("rules") {
			m.rules()
		}
	}
}

type merger struct {
	p     *model.Profile
	sub   *model.Subscription
	snap  *Snapshot
	taken map[string]bool
	names map[string]string // name in the subscription → name in the profile
	d     *diag.List
}

// claim reserves a profile name for an imported object.
func (m *merger) claim(name string) string {
	final := name
	for i := 1; m.taken[final]; i++ {
		final = m.sub.Name + "/" + name
		if i > 1 {
			final += " #" + strconv.Itoa(i)
		}
	}
	m.taken[final] = true
	m.names[name] = final
	return final
}

func (m *merger) nodes() {
	keep, drop := m.regexp(m.sub.Filter, "filter"), m.regexp(m.sub.Exclude, "exclude")
	kept := 0
	for _, raw := range m.snap.Nodes {
		n := model.NewNode(raw, m.sub.Pos)
		if (keep != nil && !keep.MatchString(n.Name)) || (drop != nil && drop.MatchString(n.Name)) {
			continue
		}
		// A broken node is left out, not allowed to break the profile.
		orig := n.Name
		if strings.TrimSpace(orig) == "" {
			m.d.Warnf(m.sub.Pos, "订阅 %q 里有一个节点没有名字，已跳过", m.sub.Name)
			continue
		}
		if n.View.Type == "" {
			m.d.Warnf(m.sub.Pos, "订阅 %q 的节点 %q 没有写 type，已跳过", m.sub.Name, orig)
			continue
		}
		// Claimed as the compiler will spell it, so two names that only
		// differ in what it cleans up ("a", "a ") cannot collide later.
		n.Name = m.claim(compile.Sanitize(orig))
		m.names[orig] = n.Name
		model.SetKey(n.Raw, "name", model.Str(n.Name))
		m.p.Nodes = append(m.p.Nodes, n)
		kept++
	}
	if kept == 0 {
		m.d.Warnf(m.sub.Pos, "订阅 %q 过滤后没有剩下任何节点", m.sub.Name)
	}
	// A node that dials through another follows that node's new name.
	for _, n := range m.p.Nodes[len(m.p.Nodes)-kept:] {
		if via := n.View.DialerProxy; via != "" {
			if renamed, ok := m.names[via]; ok && renamed != via {
				model.SetKey(n.Raw, "dialer-proxy", model.Str(renamed))
				n.View.DialerProxy = renamed
			}
		}
	}
}

func (m *merger) regexp(expr, field string) *rx.Regexp {
	if expr == "" {
		return nil
	}
	re, err := rx.Compile(expr)
	if err != nil {
		m.d.Errorf(m.sub.Pos, "订阅 %q 的 %s 不是有效的正则表达式：%v", m.sub.Name, field, err)
		return nil
	}
	return re
}

func (m *merger) groups() {
	type pending struct {
		raw   *yaml.Node
		name  string
		typ   string
		group *model.Group
		chain *model.Chain
	}
	var all []string
	for _, raw := range m.snap.Nodes {
		all = append(all, model.WeakString(model.Lookup(raw, "name")))
	}
	// Name every group first: groups refer to each other by name.
	var list []*pending
	for _, raw := range m.snap.Groups {
		name := model.WeakString(model.Lookup(raw, "name"))
		if name == "" {
			continue
		}
		list = append(list, &pending{raw: raw, name: m.claim(name), typ: strings.ToLower(model.WeakString(model.Lookup(raw, "type")))})
	}
	for _, g := range list {
		members := m.members(g.raw, all)
		if g.typ == "relay" {
			// relay groups were removed from mihomo; a chain does the same.
			if len(members) < 2 {
				m.d.Warnf(m.sub.Pos, "订阅 %q 的 relay 组 %q 不到两跳，已忽略", m.sub.Name, g.name)
				continue
			}
			m.p.Chains = append(m.p.Chains, &model.Chain{Name: g.name, Hops: members, Pos: m.sub.Pos})
			continue
		}
		if len(members) == 0 {
			if fb := model.WeakString(model.Lookup(g.raw, "empty-fallback")); fb != "" && (slices.Contains(builtins, fb) || m.names[fb] != "") {
				members = []string{cmp.Or(m.names[fb], fb)} // the group's own fallback, as in mihomo
			} else {
				// Fail closed: an emptied group must not silently go direct.
				m.d.Warnf(m.sub.Pos, "订阅 %q 的出口组 %q 没有可用的成员，暂时设为屏蔽", m.sub.Name, g.name)
				members = []string{"REJECT"}
			}
		}
		typ := g.typ
		switch typ {
		case "select", "url-test", "fallback", "load-balance":
		default:
			m.d.Warnf(m.sub.Pos, "订阅 %q 的出口组 %q 类型 %q 不受支持，按手动选择处理", m.sub.Name, g.name, typ)
			typ = "select"
		}
		raw := g.raw
		grp := &model.Group{Name: g.name, Type: typ, Members: members, Pos: m.sub.Pos}
		grp.URL = model.WeakString(model.Lookup(raw, "url"))
		grp.Interval, _ = model.WeakInt(model.Lookup(raw, "interval"))
		grp.Tolerance, _ = model.WeakInt(model.Lookup(raw, "tolerance"))
		grp.Strategy = model.WeakString(model.Lookup(raw, "strategy"))
		if lazy, ok := model.WeakBool(model.Lookup(raw, "lazy")); ok {
			grp.Lazy = &lazy
		}
		grp.Timeout, _ = model.WeakInt(model.Lookup(raw, "timeout"))
		grp.MaxFailedTimes, _ = model.WeakInt(model.Lookup(raw, "max-failed-times"))
		grp.ExpectedStatus = model.WeakString(model.Lookup(raw, "expected-status"))
		grp.DisableUDP, _ = model.WeakBool(model.Lookup(raw, "disable-udp"))
		grp.Hidden, _ = model.WeakBool(model.Lookup(raw, "hidden"))
		grp.Icon = model.WeakString(model.Lookup(raw, "icon"))
		m.p.Groups = append(m.p.Groups, grp)
	}
}

// members resolves a Clash group's members as mihomo does: listed names;
// provider nodes (use, include-all-providers) and all nodes (include-all,
// include-all-proxies), which filter narrows, in the order of its
// expressions; then exclude-filter and exclude-type take members out,
// listed ones too.
func (m *merger) members(raw *yaml.Node, all []string) []string {
	type member struct{ sub, final string } // subscription-side and final names
	var out []member
	add := func(sub, final string) {
		if !slices.ContainsFunc(out, func(x member) bool { return x.final == final }) {
			out = append(out, member{sub, final})
		}
	}
	if n := model.Lookup(raw, "proxies"); n != nil {
		for _, c := range n.Content {
			name := model.WeakString(c)
			switch {
			case slices.Contains(builtins, name):
				add(name, name)
			case m.names[name] != "":
				add(name, m.names[name])
			}
			// Other names were filtered out by the subscription's filter.
		}
	}
	var pool []string
	on := func(key string) bool { v, _ := model.WeakBool(model.Lookup(raw, key)); return v }
	if on("include-all") || on("include-all-providers") {
		for _, nodes := range m.snap.Providers {
			pool = append(pool, nodes...)
		}
	} else if n := model.Lookup(raw, "use"); n != nil {
		for _, c := range n.Content {
			pool = append(pool, m.snap.Providers[model.WeakString(c)]...)
		}
	}
	if on("include-all") || on("include-all-proxies") {
		pool = append(pool, all...)
	}
	if keep := m.groupRegexp(model.WeakString(model.Lookup(raw, "filter"))); keep != nil {
		var kept []string
		for _, re := range keep {
			for _, name := range pool {
				if re.MatchString(name) && !slices.Contains(kept, name) {
					kept = append(kept, name)
				}
			}
		}
		pool = kept
	}
	for _, name := range pool {
		if final, ok := m.names[name]; ok {
			add(name, final)
		}
	}
	drop := m.groupRegexp(model.WeakString(model.Lookup(raw, "exclude-filter")))
	var types []string
	for t := range strings.SplitSeq(model.WeakString(model.Lookup(raw, "exclude-type")), "|") {
		if t = strings.TrimSpace(t); t != "" {
			types = append(types, strings.ToLower(t))
		}
	}
	var names []string
	for _, x := range out {
		if drop.MatchString(x.sub) || len(types) > 0 && slices.Contains(types, m.adapterType(x.sub)) {
			continue
		}
		names = append(names, x.final)
	}
	return names
}

// adapterType is a subscription member's type as mihomo's exclude-type
// compares it: its adapter's name, in lower case.
func (m *merger) adapterType(name string) string {
	if slices.Contains(builtins, name) {
		return strings.ToLower(name)
	}
	for _, raw := range m.snap.Nodes {
		if model.WeakString(model.Lookup(raw, "name")) == name {
			switch t := strings.ToLower(model.WeakString(model.Lookup(raw, "type"))); t {
			case "ss":
				return "shadowsocks"
			case "ssr":
				return "shadowsocksr"
			default:
				return t
			}
		}
	}
	for _, raw := range m.snap.Groups {
		if model.WeakString(model.Lookup(raw, "name")) == name {
			t := strings.ToLower(model.WeakString(model.Lookup(raw, "type")))
			return map[string]string{"select": "selector", "url-test": "urltest", "fallback": "fallback", "load-balance": "loadbalance", "relay": "relay"}[t]
		}
	}
	return ""
}

// groupRegexp compiles a group's filter: expressions as mihomo reads
// them, several separated by backticks. One that cannot be read is
// ignored with a warning.
func (m *merger) groupRegexp(expr string) rx.List {
	if expr == "" {
		return nil
	}
	re, err := rx.CompileList(expr)
	if err != nil {
		m.d.Warnf(m.sub.Pos, "订阅 %q 的正则表达式 %q 无法使用（%v），已忽略这个过滤条件", m.sub.Name, expr, err)
		return nil
	}
	return re
}

func (m *merger) rules() {
	imp := &model.ImportedRules{Pos: m.sub.Pos, Providers: map[string]*model.RuleProvider{}}
	for _, line := range m.snap.Rules {
		fields := strings.Split(line, ",")
		for i := range fields {
			fields[i] = strings.TrimSpace(fields[i])
		}
		idx, err := route.TargetField(fields)
		if err != nil {
			m.d.Warnf(m.sub.Pos, "订阅 %q：跳过规则 %q：%v", m.sub.Name, line, err)
			continue
		}
		if final, ok := m.names[fields[idx]]; ok {
			fields[idx] = final
		}
		imp.Lines = append(imp.Lines, strings.Join(fields, ","))
	}
	for name, rp := range m.snap.RuleProviders {
		cp := *rp
		cp.Name = m.sub.Name + "-" + name
		imp.Providers[name] = &cp
	}
	if m.p.Routes.Imported == nil {
		m.p.Routes.Imported = map[string]*model.ImportedRules{}
	}
	m.p.Routes.Imported[m.sub.Name] = imp
	// Rules nobody placed in the table go last, so manual entries and the
	// user's own lists still win.
	if !slices.ContainsFunc(m.p.Routes.Lists, func(l *model.ListRef) bool { return l.List == m.sub.Name }) {
		m.p.Routes.Lists = append(m.p.Routes.Lists, &model.ListRef{List: m.sub.Name, Pos: m.sub.Pos})
	}
}

// Summary describes what a snapshot contains, for CLI output.
func (s *Snapshot) Summary() string {
	return fmt.Sprintf("%d 个节点，%d 个出口组，%d 条规则", len(s.Nodes), len(s.Groups), len(s.Rules))
}
