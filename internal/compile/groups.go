package compile

import (
	"regexp"
	"slices"
	"strings"
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
		if len(grp.Members) == 0 && !badMember {
			c.d.Errorf(g.Pos, "出口组 %q 没有任何成员", grp.Name)
		}
		grp.URL, grp.Interval, grp.Tolerance, grp.Lazy, grp.Strategy = g.URL, g.Interval, g.Tolerance, g.Lazy, g.Strategy
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

// applyFilter adds every node whose name matches the regexp, in profile order.
func (c *compiler) applyFilter(grp *Group, expr string) {
	re, err := regexp.Compile(expr)
	if err != nil {
		c.d.Errorf(grp.Pos, "出口组 %q 的 filter 不是有效的正则表达式：%v", grp.Name, err)
		return
	}
	matched := 0
	for _, p := range c.res.Proxies {
		if p.Kind == ProxyNode && re.MatchString(p.Name) {
			matched++
			if !slices.Contains(grp.Members, p.Name) {
				grp.Members = append(grp.Members, p.Name)
			}
		}
	}
	if matched == 0 {
		c.d.Warnf(grp.Pos, "出口组 %q 的 filter %q 没有匹配到任何节点", grp.Name, expr)
	}
}

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
