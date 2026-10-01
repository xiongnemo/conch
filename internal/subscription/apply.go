package subscription

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"nautilus/internal/diag"
	"nautilus/internal/model"
	"nautilus/internal/route"
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
		n.Name = m.claim(n.Name)
		model.SetKey(n.Raw, "name", model.Str(n.Name))
		m.p.Nodes = append(m.p.Nodes, n)
		kept++
	}
	if kept == 0 {
		m.d.Warnf(m.sub.Pos, "订阅 %q 过滤后没有剩下任何节点", m.sub.Name)
	}
}

func (m *merger) regexp(expr, field string) *regexp.Regexp {
	if expr == "" {
		return nil
	}
	re, err := regexp.Compile(expr)
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
			// Fail closed: an emptied group must not silently go direct.
			m.d.Warnf(m.sub.Pos, "订阅 %q 的出口组 %q 没有可用的成员，暂时设为屏蔽", m.sub.Name, g.name)
			members = []string{"REJECT"}
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
		m.p.Groups = append(m.p.Groups, grp)
	}
}

// members resolves a Clash group's members: listed names, provider nodes
// (use), and all nodes (include-all), narrowed by filter/exclude-filter.
func (m *merger) members(raw *yaml.Node, all []string) []string {
	var out []string
	add := func(name string) {
		if !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	if n := model.Lookup(raw, "proxies"); n != nil {
		for _, c := range n.Content {
			name := model.WeakString(c)
			switch {
			case slices.Contains(builtins, name):
				add(name)
			case m.names[name] != "":
				add(m.names[name])
			}
			// Other names were filtered out by the subscription's filter.
		}
	}
	// pool holds subscription-side names; filters apply to those.
	var pool []string
	if n := model.Lookup(raw, "use"); n != nil {
		for _, c := range n.Content {
			pool = append(pool, m.snap.Providers[model.WeakString(c)]...)
		}
	}
	for _, key := range []string{"include-all", "include-all-proxies"} {
		if on, _ := model.WeakBool(model.Lookup(raw, key)); on {
			pool = append(pool, all...)
		}
	}
	keep := m.groupRegexp(model.WeakString(model.Lookup(raw, "filter")))
	drop := m.groupRegexp(model.WeakString(model.Lookup(raw, "exclude-filter")))
	for _, name := range pool {
		if (keep != nil && !keep.MatchString(name)) || (drop != nil && drop.MatchString(name)) {
			continue
		}
		if final, ok := m.names[name]; ok {
			add(final)
		}
	}
	return out
}

// groupRegexp compiles a group's filter. A filter Go cannot compile (for
// example one using lookahead) is ignored with a warning.
func (m *merger) groupRegexp(expr string) *regexp.Regexp {
	if expr == "" {
		return nil
	}
	re, err := regexp.Compile(expr)
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
