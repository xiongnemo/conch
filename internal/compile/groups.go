package compile

import (
	"slices"
	"strings"

	"github.com/xiongnemo/conch/internal/model"
	"github.com/xiongnemo/conch/internal/rx"
)

var groupTypes = map[string]string{
	"select":       "select",
	"url-test":     "url-test",
	"auto":         "url-test",
	"fallback":     "fallback",
	"load-balance": "load-balance",
}

const (
	defaultTestURL      = "https://www.gstatic.com/generate_204"
	defaultTestInterval = 300
)

func (c *compiler) resolveGroups() {
	for _, g := range c.p.Groups {
		e := c.names[sanitize(g.Name)]
		if e == nil || e.kind != kGroup || e.pos != g.Pos {
			continue // rejected as a duplicate in declare
		}
		grp := e.group
		typ, ok := groupTypes[strings.ToLower(strings.TrimSpace(g.Type))]
		if !ok {
			c.d.Errorf(g.Pos, "出口组 %q 的 type 应该是 select、url-test、fallback 或 load-balance", grp.Name)
		}
		grp.Type = typ
		badMember := false
		for _, m := range g.Members {
			name := sanitize(m)
			switch {
			case c.names[name] == nil:
				c.d.Errorf(g.Pos, "出口组 %q 的成员 %q 不存在", grp.Name, m)
				badMember = true
			case name == grp.Name:
				c.d.Errorf(g.Pos, "出口组 %q 不能包含它自己", grp.Name)
				badMember = true
			case !slices.Contains(grp.Members, name):
				grp.Members = append(grp.Members, name)
			}
		}
		if g.Filter != "" {
			c.applyFilter(grp, g.Filter)
		}
		c.exclude(grp, g)
		if len(grp.Members) == 0 && !badMember {
			if fb := sanitize(g.EmptyFallback); fb != "" && c.names[fb] != nil && fb != grp.Name {
				grp.Members = []string{fb}
			} else {
				c.d.Errorf(g.Pos, "出口组 %q 没有任何成员", grp.Name)
			}
		}
		grp.URL, grp.Interval, grp.Tolerance, grp.Lazy, grp.Strategy = g.URL, g.Interval, g.Tolerance, g.Lazy, g.Strategy
		grp.Timeout, grp.MaxFailedTimes, grp.ExpectedStatus = g.Timeout, g.MaxFailedTimes, strings.TrimSpace(g.ExpectedStatus)
		grp.DisableUDP, grp.Hidden, grp.Icon = g.DisableUDP, g.Hidden, g.Icon
		if typ != "select" {
			if grp.URL == "" {
				grp.URL = defaultTestURL
			}
			if grp.Interval == 0 {
				grp.Interval = defaultTestInterval
			}
		}
	}
}

// applyFilter adds every node whose name matches the filter: regexps as
// mihomo writes them, several separated by backticks, in the order of the
// expressions and then of the profile.
func (c *compiler) applyFilter(grp *Group, expr string) {
	list, err := rx.CompileList(expr)
	if err != nil {
		c.d.Errorf(grp.Pos, "出口组 %q 的 filter 不是有效的正则表达式：%v", grp.Name, err)
		return
	}
	matched := 0
	for _, re := range list {
		for _, p := range c.res.Proxies {
			if p.Kind == ProxyNode && re.MatchString(p.Name) {
				matched++
				if !slices.Contains(grp.Members, p.Name) {
					grp.Members = append(grp.Members, p.Name)
				}
			}
		}
	}
	if matched == 0 {
		c.d.Warnf(grp.Pos, "出口组 %q 的 filter %q 没有匹配到任何节点", grp.Name, expr)
	}
}

// exclude takes out the members exclude-filter or exclude-type name, as
// mihomo does with every member, listed ones too.
func (c *compiler) exclude(grp *Group, g *model.Group) {
	var drop rx.List
	if g.ExcludeFilter != "" {
		var err error
		if drop, err = rx.CompileList(g.ExcludeFilter); err != nil {
			c.d.Errorf(g.Pos, "出口组 %q 的 exclude-filter 不是有效的正则表达式：%v", grp.Name, err)
			return
		}
	}
	var types []string
	for t := range strings.SplitSeq(g.ExcludeType, "|") {
		if t = strings.TrimSpace(t); t != "" {
			types = append(types, strings.ToLower(t))
		}
	}
	if drop == nil && types == nil {
		return
	}
	grp.Members = slices.DeleteFunc(grp.Members, func(m string) bool {
		return drop.MatchString(m) || slices.Contains(types, c.adapterType(m))
	})
}

// adapterType is the type mihomo's exclude-type compares: its adapters'
// names (Shadowsocks, Socks5, Selector…), in lower case.
func (c *compiler) adapterType(name string) string {
	e := c.names[name]
	if e == nil {
		return ""
	}
	switch e.kind {
	case kNode:
		t := strings.ToLower(e.node.View.Type)
		if a, ok := adapterTypes[t]; ok {
			return a
		}
		return t
	case kGroup:
		for _, g := range c.p.Groups {
			if sanitize(g.Name) == name {
				return groupAdapterTypes[groupTypes[strings.ToLower(strings.TrimSpace(g.Type))]]
			}
		}
	case kChain:
		return "relay"
	case kBuiltin:
		return strings.ToLower(name)
	}
	return ""
}

var adapterTypes = map[string]string{"ss": "shadowsocks", "ssr": "shadowsocksr"}

var groupAdapterTypes = map[string]string{"select": "selector", "url-test": "urltest", "fallback": "fallback", "load-balance": "loadbalance"}

// addGlobal emits an explicit GLOBAL group listing only user-visible
// outbounds, so mihomo does not build one that includes every chain hop.
func (c *compiler) addGlobal() {
	g := &Group{Name: GlobalGroup, Type: "select"}
	for _, grp := range c.res.Groups {
		if grp.Chain == "" {
			g.Members = append(g.Members, grp.Name)
		}
	}
	for _, ch := range c.res.Chains {
		g.Members = append(g.Members, ch.Name)
	}
	for _, p := range c.res.Proxies {
		if p.Kind == ProxyNode {
			g.Members = append(g.Members, p.Name)
		}
	}
	g.Members = append(g.Members, "DIRECT")
	c.res.Groups = append(c.res.Groups, g)
}
