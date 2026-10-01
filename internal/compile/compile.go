// Package compile resolves a profile into a backend-neutral result: every
// outbound has a unique emitted name, chains are expanded into per-hop
// proxies, and the routing table is ordered.
package compile

import (
	"slices"
	"strconv"
	"strings"

	"nautilus/internal/diag"
	"nautilus/internal/model"
	"nautilus/internal/route"
)

// HopSep separates parts of generated clone names. It is stripped from
// user-supplied names, so generated names can never collide with them.
const HopSep = "›"

// TagEnd is reserved for backends that need prefix-free identifiers (xray
// selects balancer members by tag prefix); user names never contain it.
const TagEnd = "»"

// GlobalGroup is the group mihomo uses in global mode.
const GlobalGroup = "GLOBAL"

// Builtin outbounds every backend provides.
var builtins = []string{"DIRECT", "REJECT", "REJECT-DROP"}

type ProxyKind int

const (
	ProxyNode      ProxyKind = iota // a node as the user defined it
	ProxyChainHop                   // an intermediate hop of a chain
	ProxyChainExit                  // the last hop of a chain; named after the chain
)

// Proxy is one emitted proxy object.
type Proxy struct {
	Name     string
	Node     *model.Node
	Upstream string // dial through this outbound (dialer-proxy); empty = direct
	Kind     ProxyKind
	Chain    string // chain name for hop/exit proxies
	Hop      int    // 1-based index of the hop within the chain
}

// Group is one emitted outbound group.
type Group struct {
	Name      string
	Type      string // select | url-test | fallback | load-balance
	Members   []string
	URL       string
	Interval  int
	Tolerance int
	Lazy      *bool
	Strategy  string
	Selected  string // select groups: the chosen member; empty means the first
	Pos       diag.Pos
	// A group at a later hop of a chain is emitted as a copy whose members
	// dial through the hop before. Chain and Hop say where it belongs;
	// such copies are not user-visible. Follows is the group it copies,
	// whose selection a select copy mirrors.
	Chain   string
	Hop     int
	Follows string
}

// Chain is a resolved chain.
type Chain struct {
	Name   string
	Hops   []string // as written (sanitized)
	Path   []string // Hops with nested chains after the first hop flattened; Path[1:] are nodes
	Inline bool     // written directly in a route instead of under chains:
	Pos    diag.Pos
}

// Result is the compiled profile.
type Result struct {
	Profile   *model.Profile
	Settings  Settings
	Proxies   []*Proxy
	Groups    []*Group
	Chains    []*Chain
	Rules     []route.Rule
	Providers []route.Provider
	Diags     diag.List
}

type kind int

const (
	kNode kind = iota + 1
	kGroup
	kChain
	kBuiltin
)

type entity struct {
	kind  kind
	node  *model.Node
	group *Group
	chain *Chain
	pos   diag.Pos
}

type compiler struct {
	p     *model.Profile
	res   *Result
	d     *diag.List
	names map[string]*entity
	// inline chains keyed by their hop list, so identical chains are shared
	inline map[string]*Chain
}

// Compile resolves p. Problems are reported in Result.Diags; the result is
// only safe to encode when Diags has no errors.
func Compile(p *model.Profile) *Result {
	res := &Result{Profile: p}
	c := &compiler{p: p, res: res, d: &res.Diags, names: map[string]*entity{}, inline: map[string]*Chain{}}
	res.Settings = c.settings()
	c.declare()
	c.collectInlineChains()
	c.resolveGroups()
	c.resolveChains()
	if !c.d.HasErrors() {
		c.checkCycles()
	}
	if !c.d.HasErrors() {
		c.expandChains()
		c.checkUDP()
	}
	c.addGlobal()
	tab := route.Build(&p.Routes, c.resolveVia, c.d)
	res.Rules, res.Providers = tab.Rules, tab.Providers
	res.globalStartsAtDefault()
	return res
}

// globalStartsAtDefault puts the default exit first in GLOBAL, so global
// mode sends everything where unmatched traffic goes until the user picks
// another member.
func (r *Result) globalStartsAtDefault() {
	i := slices.IndexFunc(r.Rules, func(rule route.Rule) bool { return rule.Match == route.MatchFinal })
	if i < 0 {
		return
	}
	for _, g := range r.Groups {
		if g.Name != GlobalGroup {
			continue
		}
		if j := slices.Index(g.Members, r.Rules[i].Target); j > 0 {
			g.Members = slices.Insert(slices.Delete(g.Members, j, j+1), 0, r.Rules[i].Target)
		}
	}
}

// Select records the member chosen in each select group. Unknown groups
// and members that no longer exist are ignored, so stale selections are
// harmless after the profile changes. It returns the applied selections.
func (r *Result) Select(choices map[string]string) map[string]string {
	applied := map[string]string{}
	for _, g := range r.Groups {
		if m, ok := choices[g.Name]; ok && g.Type == "select" && g.Chain == "" && slices.Contains(g.Members, m) {
			g.Selected = m
			applied[g.Name] = m
		}
	}
	for _, g := range r.Groups {
		if g.Follows != "" && g.Type == "select" {
			g.Selected = r.FollowingMember(g, r.group(g.Follows).Selected)
		}
	}
	return applied
}

func (r *Result) group(name string) *Group {
	for _, g := range r.Groups {
		if g.Name == name {
			return g
		}
	}
	return &Group{}
}

// FollowingMember is the member of a copied group that stands for member
// of the original; empty for the first.
func (r *Result) FollowingMember(copy *Group, member string) string {
	i := slices.Index(r.group(copy.Follows).Members, member)
	if i < 0 || i >= len(copy.Members) {
		return ""
	}
	return copy.Members[i]
}

// sanitize makes a name safe for every backend: Clash rule lines split on
// commas and trim spaces, and HopSep and TagEnd are reserved.
func sanitize(name string) string {
	name = strings.TrimSpace(name)
	name = strings.ReplaceAll(name, ",", "，")
	name = strings.ReplaceAll(name, TagEnd, ">>")
	return strings.ReplaceAll(name, HopSep, ">")
}

func (c *compiler) define(name string, e *entity, what string) bool {
	if name == "" {
		c.d.Errorf(e.pos, "%s缺少名字", what)
		return false
	}
	if slices.Contains(builtins, name) || name == GlobalGroup {
		c.d.Errorf(e.pos, "%q 是保留名字，请换一个", name)
		return false
	}
	if prev, ok := c.names[name]; ok {
		c.d.Errorf(e.pos, "名字 %q 重复了（另一个在 %s）", name, prev.pos)
		return false
	}
	c.names[name] = e
	return true
}

func (c *compiler) declare() {
	for _, b := range builtins {
		c.names[b] = &entity{kind: kBuiltin}
	}
	for _, n := range c.p.Nodes {
		name := sanitize(n.Name)
		if name != n.Name && n.Name != "" {
			c.d.Warnf(n.Pos, "节点名 %q 含有逗号等特殊字符，已改为 %q", n.Name, name)
		}
		n.Name = name
		if n.View.Type == "" {
			c.d.Errorf(n.Pos, "节点 %q 缺少 type", name)
		}
		if c.define(name, &entity{kind: kNode, node: n, pos: n.Pos}, "节点") {
			// A hand-written dialer-proxy is kept, but must follow renames.
			c.res.Proxies = append(c.res.Proxies, &Proxy{Name: name, Node: n, Kind: ProxyNode, Upstream: sanitize(n.View.DialerProxy)})
		}
	}
	for _, g := range c.p.Groups {
		grp := &Group{Name: sanitize(g.Name), Pos: g.Pos}
		if c.define(grp.Name, &entity{kind: kGroup, group: grp, pos: g.Pos}, "出口组") {
			c.res.Groups = append(c.res.Groups, grp)
		}
	}
	for _, ch := range c.p.Chains {
		chain := &Chain{Name: sanitize(ch.Name), Pos: ch.Pos}
		for _, h := range ch.Hops {
			chain.Hops = append(chain.Hops, sanitize(h))
		}
		if c.define(chain.Name, &entity{kind: kChain, chain: chain, pos: ch.Pos}, "链") {
			c.res.Chains = append(c.res.Chains, chain)
		}
	}
}

// collectInlineChains registers chains written directly in routes, such as
// "claude.ai: [香港自动, home]". Identical hop lists share one chain, and a
// named chain with the same hops is reused.
func (c *compiler) collectInlineChains() {
	type viaAt struct {
		via model.Via
		pos diag.Pos
	}
	vias := []viaAt{{c.p.Routes.Default, diag.Pos{}}}
	for _, e := range c.p.Routes.Entries {
		vias = append(vias, viaAt{e.Via, e.Pos})
	}
	for _, l := range c.p.Routes.Lists {
		vias = append(vias, viaAt{l.Via, l.Pos})
	}
	for _, v := range vias {
		if v.via.Chain == nil {
			continue
		}
		hops := sanitizeAll(v.via.Chain)
		key := strings.Join(hops, "\x00")
		if _, ok := c.inline[key]; ok {
			continue
		}
		if named := c.namedChainWithHops(hops); named != nil {
			c.inline[key] = named
			continue
		}
		chain := &Chain{Name: strings.Join(hops, "→"), Hops: hops, Inline: true, Pos: v.pos}
		for n := 2; c.names[chain.Name] != nil; n++ {
			chain.Name = strings.Join(hops, "→") + " #" + strconv.Itoa(n)
		}
		c.names[chain.Name] = &entity{kind: kChain, chain: chain, pos: v.pos}
		c.inline[key] = chain
		c.res.Chains = append(c.res.Chains, chain)
	}
}

func (c *compiler) namedChainWithHops(hops []string) *Chain {
	for _, ch := range c.res.Chains {
		if !ch.Inline && slices.Equal(ch.Hops, hops) {
			return ch
		}
	}
	return nil
}

// resolveVia is the route.Resolver: it maps a via to an emitted name.
func (c *compiler) resolveVia(v model.Via, pos diag.Pos) (string, bool) {
	if v.Chain != nil {
		ch, ok := c.inline[strings.Join(sanitizeAll(v.Chain), "\x00")]
		return ch.Name, ok
	}
	name := sanitize(v.Name)
	e := c.names[name]
	if e == nil {
		c.d.Errorf(pos, "找不到出口 %q", v.Name)
		return "", false
	}
	return name, true
}

func sanitizeAll(names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = sanitize(n)
	}
	return out
}
